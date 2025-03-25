# Windows 10 Debloat Script

A PowerShell script to disable unwanted Windows 10 features and services. Designed to be idempotent (safely re-runnable) after Windows updates.

## DISCLAIMER

**This script is provided "as is" without warranty of any kind, express or implied. The author is not responsible for any damages or data loss that may result from using this script. Use at your own risk.**

## Features

- Disables telemetry/data collection
- Disables Cortana and web search
- Removes OneDrive
- Contains Microsoft Edge
- Handles browser installation and defaults
- Dry-run mode to preview changes before applying

## Requirements

- Windows 10
- PowerShell 5.0+
- Administrative privileges

## Usage

### Basic Usage

Run the script with administrator privileges:

```powershell
# Run with execution policy bypass
powershell -ExecutionPolicy Bypass -File "path\to\win10debloat.ps1"
```

This runs in dry-run mode by default, showing all operations that would be performed without making actual changes.

To apply changes:

```powershell
powershell -ExecutionPolicy Bypass -File "path\to\win10debloat.ps1" -Apply
```

### Targeted Operations

Select specific operations with parameters:

```powershell
# Dry run for specific features
powershell -ExecutionPolicy Bypass -File "path\to\win10debloat.ps1" -Telemetry -Edge

# Apply changes for specific features
powershell -ExecutionPolicy Bypass -File "path\to\win10debloat.ps1" -Telemetry -Edge -Apply
```

Available parameters:
- `-Telemetry`: Disable Windows telemetry/data collection
- `-Cortana`: Disable Cortana and related features
- `-OneDrive`: Remove OneDrive and prevent reinstallation
- `-WebSearch`: Disable web search in taskbar
- `-Edge`: Contain Microsoft Edge browser
- `-Firefox`: Install/use Firefox and set as default
- `-Chrome`: Install/use Chrome and set as default
- `-All`: Run all operations (default if no parameters specified)
- `-DryRun`: Preview changes without applying them (default behavior)
- `-Apply`: Actually apply changes (overrides -DryRun)

### Browser Handling

The script intelligently manages browser installation and defaults:

- If a specific browser is requested via `-Firefox` or `-Chrome`, it will be installed (if needed) and set as default
- If both browsers exist with a default already set, no changes are made without a specific parameter
- For systems with no browsers, Firefox is installed by default
- If only one browser exists, it's used without installing another

## Output

The script provides color-coded status messages:
- Green: Successful operations
- Magenta: Actions that would be performed (dry-run mode)
- Yellow: Warnings requiring manual steps
- Red: Critical errors
- White: Information and follow-up instructions

## Notes

- Some browser default settings require manual confirmation due to Windows 10 restrictions
- Some features may be re-enabled by Windows updates; re-run the script as needed
- Edge cannot be completely removed without risking system instability

## License

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/).

You are free to:
- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

Under the following terms:
- Attribution — You must give appropriate credit
- NonCommercial — You may not use the material for commercial purposes
- ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original
