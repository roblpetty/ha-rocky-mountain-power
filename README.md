# Rocky Mountain Power

[![GitHub Release][releases-shield]][releases]
[![GitHub Activity][commits-shield]][commits]
[![License][license-shield]](LICENSE)

[![hacs][hacsbadge]][hacs]
![Project Maintenance][maintenance-shield]
[![BuyMeCoffee][buymecoffeebadge]][buymecoffee]

[![Community Forum][forum-shield]][forum]

_Component to integrate with [Rocky Mountain Power][rmp]._

<img src="rmp.png" alt="Rocky Mountain Power" width="250">

## Installation

### Option 1: HACS (Recommended)

[![Open your Home Assistant instance and open this repository in HACS][hacs-repository-badge]][hacs-repository]

1. Click the button above, or open HACS in Home Assistant.
2. Go to HACS -> Integrations -> three dots menu -> Custom repositories.
3. Add `https://github.com/AurelioB/ha-rocky-mountain-power` as an Integration.
4. Search for "Rocky Mountain Power" and install it.
5. Restart Home Assistant.
6. Continue to Configuration.

### Option 2: Manual Installation

1. Download the latest release from [GitHub Releases][releases].
2. Extract the release and copy `custom_components/rocky_mountain_power` to your Home Assistant `custom_components` directory:

    ```text
    config/
    └── custom_components/
        └── rocky_mountain_power/
            ├── __init__.py
            ├── config_flow.py
            ├── manifest.json
            └── ...
    ```

3. Restart Home Assistant.
4. Continue to Configuration.

Manual installs do not receive HACS update notifications.

## Configuration is done in the UI

[![Open your Home Assistant instance and start setting up Rocky Mountain Power][config-flow-badge]][config-flow]

Before continuing, make sure to turn off Multi Factor Authentication from your
Rocky Mountain Power account. You can turn it off from the "Manage account" link on the left side of the page.

1. Click the button above, or go to Settings -> Devices & services.
2. Click Add Integration and search for "Rocky Mountain Power".
3. Username: enter your Rocky Mountain Power username.
4. Password: enter your Rocky Mountain Power password.

## Sensors

The integration exposes forecasted bill cost sensors and a current bill energy
consumption sensor in kWh. It also imports historical usage/cost statistics into
Home Assistant's recorder when Rocky Mountain Power makes the data available.

## Contributions are welcome!

If you want to contribute to this please read the [Contribution guidelines](CONTRIBUTING.md)

***

[rmp]: https://www.rockymountainpower.net
[buymecoffee]: https://www.buymeacoffee.com/jaredhobbs
[buymecoffeebadge]: https://img.shields.io/badge/buy%20me%20a%20coffee-donate-yellow.svg?style=for-the-badge
[commits-shield]: https://img.shields.io/github/commit-activity/y/AurelioB/rocky-mountain-power.svg?style=for-the-badge
[commits]: https://github.com/AurelioB/rocky-mountain-power/commits/main
[config-flow-badge]: https://my.home-assistant.io/badges/config_flow_start.svg
[config-flow]: https://my.home-assistant.io/redirect/config_flow_start/?domain=rocky_mountain_power
[hacs]: https://github.com/custom-components/hacs
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[hacs-repository-badge]: https://my.home-assistant.io/badges/hacs_repository.svg
[hacs-repository]: https://my.home-assistant.io/redirect/hacs_repository/?owner=AurelioB&repository=rocky-mountain-power&category=integration
[forum-shield]: https://img.shields.io/badge/community-forum-brightgreen.svg?style=for-the-badge
[forum]: https://community.home-assistant.io/
[license-shield]: https://img.shields.io/github/license/AurelioB/rocky-mountain-power.svg?style=for-the-badge
[maintenance-shield]: https://img.shields.io/badge/maintainer-Jared%20Hobbs%20%40jaredhobbs-blue.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/AurelioB/rocky-mountain-power.svg?style=for-the-badge
[releases]: https://github.com/AurelioB/rocky-mountain-power/releases
