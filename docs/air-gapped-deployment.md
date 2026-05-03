# Air-Gapped Deployment

VanGuard is designed for air-gapped environments where no internet access is available.

## Preparation (connected machine)

1. Download all tools via **Configuration > Tool Management**
2. Download all rules via **Update Tools & Rules**
3. Optionally create an offline update bundle: **Update > Create Offline Bundle**
4. Copy the entire VanGuard directory to a USB drive

## Deployment (air-gapped machine)

1. Insert USB drive
2. Run `vanguard.exe` (Windows) or `./vanguard` (Linux) directly from USB
3. All tools, rules, and configurations are self-contained
4. Evidence output is written to `output/` on the USB drive

## Offline Updates

To update rules on an air-gapped system:

1. On a connected machine: **Update > Create Offline Bundle**
2. Transfer the bundle ZIP to the air-gapped system
3. On the air-gapped system: **Update > Apply Offline Bundle**
4. SHA256 verification is performed automatically
