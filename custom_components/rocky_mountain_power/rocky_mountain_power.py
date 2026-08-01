"""Implementation of Rocky Mountain Power API."""
from __future__ import annotations

import base64
import html
import locale
import dataclasses
from datetime import date, datetime, time as datetime_time, timedelta
from enum import Enum
import json
import logging
import re
from http.cookiejar import CookieJar
from typing import Any, Optional
from urllib import error, parse, request

import arrow

_LOGGER = logging.getLogger(__file__)
DEBUG_LOG_RESPONSE = False
locale.setlocale(locale.LC_ALL, "en_US")


def _b64decode(value: str) -> bytes:
    """Decode padded or unpadded base64 text."""
    return base64.b64decode(value + "=" * (-len(value) % 4))


def _lookup(value: Any, key: str) -> Any:
    """Find a key anywhere in a nested dict/list response."""
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = _lookup(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _lookup(child, key)
            if found is not None:
                return found
    return None


def _first(value: dict[str, Any], dotted_path: str) -> dict[str, Any]:
    """Return the first object at a dotted response path."""
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return {}
        current = current.get(part)
    if isinstance(current, list):
        return current[0] if current else {}
    if isinstance(current, dict):
        return current
    return {}


class RockyMountainPowerUtility:
    """HTTP client for the Rocky Mountain Power web app."""

    BASE_URL = "https://csapps.rockymountainpower.net"
    LOGIN_URL = "https://csapps.rockymountainpower.net/idm/login"
    AUTHORIZE_URL = "https://csapps.rockymountainpower.net/oauth2/authorization/B2C_1A_PAC_SIGNIN"
    B2C_BASE_URL = "https://login.csapps.rockymountainpower.net"
    TZ = "America/Denver"

    def __init__(self) -> None:
        self.user_id = None
        self.web_user_id = None
        self.account = {}
        self.agreement = {}
        self.forecast = {}
        self._cookies = CookieJar()
        self._opener = None
        self._aes_key: bytes | None = None
        self._signing_key = None
        self._encryption_key = None

    def on_quit(self, *args: Any, **kwargs: Any) -> None:
        """Close the logical session."""
        self._aes_key = None

    def login(self, username: str, password: str) -> None:
        """Log in and load the active account."""
        try:
            self._opener = request.build_opener(
                request.HTTPCookieProcessor(self._cookies),
                request.HTTPRedirectHandler(),
            )
            self._request("GET", self.LOGIN_URL)
            self._handshake()
            auth_html = self._request("GET", self.AUTHORIZE_URL).decode()
            settings = self._parse_b2c_settings(auth_html)

            tenant = settings["hosts"]["tenant"]
            policy = settings["hosts"]["policy"]
            trans_id = settings["transId"]
            csrf = settings["csrf"]
            authorize_url = self.AUTHORIZE_URL

            login_url = (
                f"{self.B2C_BASE_URL}{tenant}/SelfAsserted?"
                f"{parse.urlencode({'tx': trans_id, 'p': policy})}"
            )
            login_body = parse.urlencode(
                {
                    "request_type": "RESPONSE",
                    "signInName": username,
                    "password": password,
                }
            ).encode()
            login_response = json.loads(
                self._request(
                    "POST",
                    login_url,
                    data=login_body,
                    headers={
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                        "Origin": self.B2C_BASE_URL,
                        "Referer": authorize_url,
                        "X-CSRF-TOKEN": csrf,
                        "X-Requested-With": "XMLHttpRequest",
                    },
                )
            )
            if str(login_response.get("status")) != "200":
                raise InvalidAuth

            confirmed_url = (
                f"{self.B2C_BASE_URL}{tenant}/api/CombinedSigninAndSignup/confirmed?"
                f"{parse.urlencode({'rememberMe': 'false', 'csrf_token': csrf, 'tx': trans_id, 'p': policy})}"
            )
            self._request("GET", confirmed_url, headers={"Referer": authorize_url})
            self._request("GET", f"{self.BASE_URL}/secure/my-account/dashboard")

            me = self._encrypted_post("/api/user/me", {})
            self.user_id = me.get("id") or me.get("userId")
            self.web_user_id = me.get("webUserId") or me.get("webUserID") or self.user_id

            accounts = self._encrypted_post(
                "/api/self-service/getAccountList",
                {
                    "getAccountListRequestBody": {
                        "request": {"webUserID": self.web_user_id},
                        "domain": {"pacifiCorpSubsidiary": "RockyMountainPower"},
                    }
                },
            )
            self.account = _first(
                accounts,
                "getAccountListResponseBody.accountList.webAccount",
            )
            self._load_agreement()
        except InvalidAuth:
            raise
        except error.HTTPError as err:
            if err.code in (400, 401, 403):
                raise InvalidAuth from err
            raise CannotConnect from err
        except Exception as err:
            raise CannotConnect from err

    def _request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        req = request.Request(
            url,
            data=data,
            method=method,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36"
                ),
                **(headers or {}),
            },
        )
        if self._opener is None:
            raise CannotConnect
        with self._opener.open(req, timeout=60) as resp:
            return resp.read()

    def _handshake(self) -> None:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        self._signing_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self._encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        signing_pub = self._signing_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        encryption_pub = self._encryption_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        body = (
            base64.b64encode(signing_pub)
            + b":"
            + base64.b64encode(encryption_pub)
        )
        response = self._request(
            "POST",
            f"{self.BASE_URL}/idm/handshake",
            data=body,
            headers={
                "Accept": "text/plain, */*",
                "Content-Type": "application/octet-stream",
                "Referer": f"{self.BASE_URL}/",
                "X-WCSSS-Policy": "0",
                "X-XSRF-TOKEN": self._xsrf_token(),
            },
        )
        encrypted_key = _b64decode(response.decode().strip())
        self._aes_key = self._encryption_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _encrypted_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import os

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if self._aes_key is None or self._signing_key is None:
            raise CannotConnect
        _LOGGER.debug("Rocky Mountain Power encrypted POST %s", path)
        plaintext = json.dumps(payload, separators=(",", ":")).encode()
        signature = self._signing_key.sign(plaintext, padding.PKCS1v15(), hashes.SHA256())
        iv = os.urandom(12)
        encrypted = AESGCM(self._aes_key).encrypt(iv, plaintext, None)
        body = base64.b64encode(iv) + base64.b64encode(encrypted)
        try:
            response = self._request(
                "POST",
                f"{self.BASE_URL}{path}",
                data=body,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "Origin": self.BASE_URL,
                    "Referer": f"{self.BASE_URL}/",
                    "X-WCSSS-Content-Signature": base64.b64encode(signature).decode(),
                    "X-XSRF-TOKEN": self._xsrf_token(),
                },
            )
        except error.HTTPError as err:
            _LOGGER.error(
                "Rocky Mountain Power encrypted POST %s failed with HTTP %s",
                path,
                err.code,
            )
            raise
        return json.loads(response or b"{}")

    def _parse_b2c_settings(self, page: str) -> dict[str, Any]:
        match = re.search(r"var\s+SETTINGS\s*=\s*({.*?});", page, re.DOTALL)
        if not match:
            raise CannotConnect
        return json.loads(html.unescape(match.group(1)))

    def _xsrf_token(self) -> str:
        for cookie in self._cookies:
            if cookie.name == "XSRF-TOKEN":
                return cookie.value
        raise CannotConnect

    def _agreement_identity(self) -> dict[str, str]:
        agreement = self.agreement or self.account
        return {
            "customerIDN": str(
                _lookup(agreement, "customerIDN")
                or _lookup(self.account, "customerIDN")
                or _lookup(self.account.get("customer"), "idn")
                or ""
            ),
            "accountSequence": str(
                _lookup(agreement, "accountSequence")
                or _lookup(self.account, "accountSequence")
                or self.account.get("sequence")
                or ""
            ),
            "agreementSequence": str(
                _lookup(agreement, "agreementSequence")
                or _lookup(self.account, "agreementSequence")
                or agreement.get("sequence")
                or ""
            ),
        }

    def _load_agreement(self) -> None:
        customer_idn = _lookup(self.account, "customerIDN") or _lookup(
            self.account.get("customer"), "idn"
        )
        account_sequence = _lookup(self.account, "accountSequence") or self.account.get(
            "sequence"
        )
        if customer_idn is None or account_sequence is None:
            self.agreement = self.account
            return
        details = self._encrypted_post(
            "/api/account/getMeteredAgreements",
            {
                "getMeteredAgreementsRequestBody": {
                    "agreementRequest": {
                        "customerIDN": str(customer_idn),
                        "accountSequence": str(account_sequence),
                    },
                    "source": "WEBCS",
                }
            },
        )
        self.agreement = (
            _first(details, "getMeteredAgreementsResponseBody.meteredAgreementList.meteredAgreement")
            or _first(details, "getMeteredAgreementsResponseBody.agreementList.agreement")
            or self.account
        )

    def get_forecast(self):
        details = self._encrypted_post(
            "/api/energy-usage/getMeterType",
            {
                "getMeterTypeRequestBody": {
                    "agreement": self._agreement_identity(),
                    "webUserid": self.web_user_id,
                }
            },
        )
        # {
        #   "isAMIMeter":true,
        #   "businessUnitCode":"11441",
        #   "isAcctAMIEligible":true,
        #   "displayInvoicedUsage":false,
        #   "minDailyUsageDate":"2022-03-21",
        #   "maxDailyUsageDate":"2023-11-22",
        #   "startDateForAMIAcctView":"2023-11-14",
        #   "endDateForAMIAcctView":"2023-11-22",
        #   "operationResult":{
        #     "returnStatus":1
        #   },
        #   "highBillAlertValue":"200",
        #   "projectedCost":"170",
        #   "projectedCostHigh":"195",
        #   "projectedCostLow":"144",
        #   "noDaysIntoBillingCycle":9,
        #   "isNetMeterFlag":false
        # }
        self.forecast = details.get("getMeterTypeResponseBody", {})
        return self.forecast

    def get_usage_by_month(self):
        details = self._encrypted_post(
            "/api/account/getUsageHistoryAndGraphDataV1",
            {
                "getUsageHistoryAndGraphDataV1RequestBody": {
                    "request": {
                        "numberOfMonths": 24,
                        "agreement": self._agreement_identity(),
                    },
                    "graphView": "MONTH",
                    "graphWindow": "TWENTY_FOUR_MONTHS",
                }
            },
        )
        usage = []
        # {
        #   "usagePeriod":"Oct 2021",
        #   "usagePeriodEndDate":"2021-10-12",
        #   "invoiceAmount":"$143",
        #   "elapsedDays":29,
        #   "kwhUsageQuantity":1124.0,
        #   "kwhReverseUsageQuantity":"0.0",
        #   "onkwhUsageQuantity":"0.0",
        #   "offkwhUsageQuantity":"0.0",
        #   "invoicedUsage":"1124",
        #   "missingDataFlag":"N",
        #   "avgTemperature":"62.78"
        # },
        for d in details.get("getUsageHistoryAndGraphDataV1ResponseBody", {}).get("usageHistory", {}).get("usageHistoryLineItem", []):
            end_time = arrow.get(datetime.fromisoformat(d["usagePeriodEndDate"]), self.TZ).datetime
            try:
                start_time = end_time - timedelta(days=int(d["elapsedDays"]))
            except KeyError:
                # elapsedDays doesn't get returned in my API call
                start_time = end_time.replace(day=1)
            amount = None
            try:
                amount = locale.atof(d.get("invoiceAmount", "").strip("$")) or None
            except ValueError:
                pass
            usage.append({
                "startTime": start_time,
                "endTime": end_time - timedelta(seconds=1),
                "usage": float(d.get("kwhUsageQuantity", 0)),
                "amount": amount,
            })
        return usage

    def get_usage_by_day(self, months=1):
        usage = []
        end = arrow.now(self.TZ).date()
        start = end - timedelta(days=max(1, months or 1) * 31)
        details = self._encrypted_post(
            "/api/energy-usage/getUsageForDateRange",
            {
                "getUsageForDateRangeRequestBody": {
                    "agreement": self._agreement_identity(),
                    "dateRange": {
                        "startDate": start.isoformat(),
                        "endDate": end.isoformat(),
                    },
                    "graphView": "DAY",
                    "graphWindow": "ONE_MONTH",
                }
            },
        )
        # {
        #   "usagePeriodEndDate":"2023-10-24",
        #   "dollerAmount":"$5",
        #   "numberOfDays":1,
        #   "kwhUsageQuantity":"37.85",
        #   "kwhReverseUsageQuantity":"0.00",
        #   "avgTemperature":"56.5",
        #   "missingDataFlag":"N",
        #   "displayDollarAmount":"Y"
        # },
        for d in details.get("getUsageForDateRangeResponseBody", {}).get("dailyUsageList", {}).get("usgHistoryLineItem", []):
            usage_date = date.fromisoformat(d["usagePeriodEndDate"])
            start_time = arrow.get(datetime.combine(usage_date, datetime_time.min), self.TZ).datetime
            end_time = start_time + timedelta(days=1)
            amount = None
            try:
                amount = locale.atof(d.get("dollerAmount", "").strip("$")) or None
            except ValueError:
                pass
            usage.append({
                "startTime": start_time,
                "endTime": end_time - timedelta(seconds=1),
                "usage": float(d.get("kwhUsageQuantity", 0)),
                "amount": amount,
                "missing": d.get("missingDataFlag", "N") != "N",
            })
        return usage

    def get_usage_by_hour(self, days=1):
        usage = []
        site_idn = _lookup(self.agreement, "siteIDN") or _lookup(self.account, "siteIDN")
        register_type = _lookup(self.agreement, "registerType") or "KWH"
        service_sequence = _lookup(self.agreement, "serviceSequence") or _lookup(self.account, "serviceSequence")
        if site_idn is None or service_sequence is None:
            _LOGGER.debug("Hourly usage unavailable: missing site/service fields")
            return usage

        for offset in range(max(1, days or 1)):
            read_date = arrow.now(self.TZ).date() - timedelta(days=offset)
            details = self._encrypted_post(
                "/api/energy-usage/getIntervalUsageForDate",
                {
                    "getIntervalUsageForDateRequestBody": {
                        "request": {
                            "siteIDN": str(site_idn),
                            "registerType": str(register_type),
                            "serviceSequence": str(service_sequence),
                            "readDate": read_date.isoformat(),
                            "agreement": self._agreement_identity(),
                        }
                    }
                },
            )
            # {
            #   "readDate":"2023-11-22",
            #   "readTime":"01:00",
            #   "usage":"1.682"
            # },
            for d in details.get("getIntervalUsageForDateResponseBody", {}).get("response", {}).get("intervalDataResponse", []):
                end_time = arrow.get(datetime.fromisoformat(f"{d['readDate']}T{d['readTime'].replace('24', '00')}:00"), self.TZ).datetime
                start_time = end_time - timedelta(hours=1)
                usage.append({
                    "startTime": start_time,
                    "endTime": end_time - timedelta(seconds=1),
                    "usage": float(d.get("usage", 0)),
                    "amount": None,
                })
        return usage

    def download_daily_usage(self):
        raise NotImplementedError("Green Button download is not available without a browser session")


class CannotConnect(Exception):
    """Error to indicate we cannot connect."""


class InvalidAuth(Exception):
    """Error to indicate there is invalid auth."""


class AggregateType(Enum):
    """How to aggregate historical data."""

    MONTH = "month"
    DAY = "day"
    HOUR = "hour"

    def __str__(self) -> str:
        """Return the value of the enum."""
        return self.value


@dataclasses.dataclass
class Customer:
    """Data about a customer."""

    uuid: str


@dataclasses.dataclass
class Account:
    """Data about an account."""

    customer: Customer
    uuid: str
    utility_account_id: str


@dataclasses.dataclass
class Forecast:
    """Forecast data for an account."""

    account: Account
    start_date: date
    end_date: date
    current_date: date
    forecasted_cost: float
    forecasted_cost_low: float
    forecasted_cost_high: float
    energy_consumption: Optional[float]
    energy_consumption_estimated: Optional[float]
    energy_export: Optional[float]


@dataclasses.dataclass
class CostRead:
    """A read from the meter that has both consumption and cost data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from value field, in KWH
    provided_cost: float  # in $


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from consumption.value field, in KWH


class RockyMountainPower:
    """Class that can get historical and forecasted usage/cost from Rocky Mountain Power."""

    def __init__(
        self,
        username: str,
        password: str,
        legacy_host: str = "localhost",
    ) -> None:
        """Initialize."""
        self.username: str = username
        self.password: str = password
        self.account = {}
        self.customer_id = None
        self.utility: RockyMountainPowerUtility = RockyMountainPowerUtility()

    def login(self) -> None:
        """Login to the utility website for access.

        :raises InvalidAuth: if login information is incorrect
        :raises CannotConnect: if we receive any HTTP error
        """
        self.utility.login(
            self.username, self.password
        )
        if not self.account:
            self.account = self.utility.account
        if not self.customer_id:
            self.customer_id = self.utility.user_id

    def end_session(self) -> None:
        self.utility.on_quit()

    def get_account(self) -> Account:
        """Get the account for the signed in user."""
        account = self._get_account()
        return Account(
            customer=Customer(uuid=self.customer_id),
            uuid=account["accountNumber"],
            utility_account_id=self.customer_id,
        )

    def get_forecast(self) -> list[Forecast]:
        """Get current and forecasted usage and cost for the current monthly bill.

        One forecast for each account, typically one for electricity.
        """
        forecasts = []
        self.utility.get_forecast()
        if self.utility.forecast:
            forecast = self.utility.forecast
            start_date = arrow.get(date.fromisoformat(forecast["startDateForAMIAcctView"]), self.utility.TZ).datetime
            end_date = arrow.get(date.fromisoformat(forecast["endDateForAMIAcctView"]), self.utility.TZ).datetime
            energy_consumption = None
            energy_export = None
            try:
                energy_consumption = self.get_current_bill_energy_consumption(start_date, end_date)
            except Exception:
                _LOGGER.warning("Unable to fetch current bill energy consumption", exc_info=True)
                energy_consumption = None
            try:
                energy_consumption_estimated = self.get_current_bill_energy_consumption_estimated(
                    start_date, end_date
                )
            except Exception:
                _LOGGER.warning(
                    "Unable to fetch estimated current bill energy consumption",
                    exc_info=True,
                )
                energy_consumption_estimated = None
            try:
                energy_export = self.get_current_bill_energy_export(start_date, end_date)
            except Exception:
                _LOGGER.warning("Unable to fetch current bill energy export", exc_info=True)
                energy_export = None
            forecasts.append(
                Forecast(
                    account=Account(
                        customer=Customer(uuid=self.customer_id),
                        uuid=self.account["accountNumber"],
                        utility_account_id=self.customer_id,
                    ),
                    start_date=start_date,
                    end_date=end_date,
                    current_date=arrow.get(date.today(), self.utility.TZ).datetime,
                    forecasted_cost=float(forecast.get("projectedCost", 0)),
                    forecasted_cost_low=float(forecast.get("projectedCostLow", 0)),
                    forecasted_cost_high=float(forecast.get("projectedCostHigh", 0)),
                    energy_consumption=energy_consumption,
                    energy_consumption_estimated=energy_consumption_estimated,
                    energy_export=energy_export,
                )
            )
        return forecasts

    def get_current_bill_energy_consumption(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> float:
        """Get kWh consumption for the current billing period."""
        today = arrow.now(self.utility.TZ).date()
        months = max(1, ((today - start_date.date()).days // 31) + 1)
        reads = self.get_cost_reads(AggregateType.DAY, months)
        start = start_date.date()
        end = end_date.date()
        return sum(
            read.consumption
            for read in reads
            if start <= read.end_time.date() <= end
        )

    def get_current_bill_energy_consumption_estimated(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Optional[float]:
        """Estimate energy consumption for missing dates in the current billing period."""
        today = arrow.now(self.utility.TZ).date()
        months = max(1, ((today - start_date.date()).days // 31) + 1)
        usage = self.utility.get_usage_by_day(months=months)

        bill_reads = [
            read for read in usage
            if start_date.date() <= read["startTime"].date() <= end_date.date()
        ]
        bill_reads.sort(key=lambda read: read["startTime"])

        missing_reads = [read for read in bill_reads if read.get("missing")]
        if not missing_reads:
            return None

        estimated_missing = 0.0
        for missing_read in missing_reads:
            previous_actual = [
                read for read in bill_reads
                if read["startTime"].date() < missing_read["startTime"].date() and not read.get("missing")
            ]
            previous_actual.sort(key=lambda read: read["startTime"], reverse=True)
            previous_actual = previous_actual[:5]
            if not previous_actual:
                return None
            estimated_missing += sum(read["usage"] for read in previous_actual) / len(previous_actual)

        return estimated_missing

    def get_current_bill_energy_export(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> float:
        """Get solar export energy for the current billing period."""
        details = self.utility._encrypted_post(
            "/api/energy-usage/getUsageForDateRange",
            {
                "getUsageForDateRangeRequestBody": {
                    "agreement": self.utility._agreement_identity(),
                    "dateRange": {
                        "startDate": (start_date.date() - timedelta(days=1)).isoformat(),
                        "endDate": end_date.date().isoformat(),
                    },
                    "graphView": "DAY",
                    "graphWindow": "ONE_MONTH",
                }
            },
        )
        start = start_date.date()
        end = end_date.date()
        return sum(
            float(d.get("kwhReverseUsageQuantity", 0) or 0)
            for d in details.get("getUsageForDateRangeResponseBody", {}).get("dailyUsageList", {}).get("usgHistoryLineItem", [])
            if start <= date.fromisoformat(d["usagePeriodEndDate"]) <= end
        )

    def _get_account(self) -> Any:
        """Get account associated with the user."""
        # Cache the account
        if not self.account:
            self.login()
            self.account = self.utility.account
        assert self.account
        return self.account

    def get_cost_reads(
        self,
        aggregate_type: AggregateType,
        period: Optional[int] = 1,
    ) -> list[CostRead]:
        """Get usage and cost data for the selected account in the given date range aggregated by month/day/hour.

        The resolution is typically hour, day, or month.
        Rocky Mountain Power typically keeps historical cost data for 2 years.
        """
        reads = self._get_dated_data(aggregate_type, period=period)
        reads.sort(key=lambda x: x["startTime"])
        return [
            CostRead(
                start_time=read["startTime"],
                end_time=read["endTime"],
                consumption=read["usage"],
                provided_cost=read["amount"] or 0,
            ) for read in reads
        ]

    def _get_dated_data(
        self,
        aggregate_type: AggregateType,
        period: Optional[int] = 1,
    ) -> list[Any]:
        if aggregate_type == AggregateType.MONTH:
            return self.utility.get_usage_by_month()
        elif aggregate_type == AggregateType.DAY:
            return self.utility.get_usage_by_day(months=period)
        elif aggregate_type == AggregateType.HOUR:
            return self.utility.get_usage_by_hour(days=period)
        else:
            raise ValueError(f"aggregate_type {aggregate_type} is not valid")
