This repository contains a highly configurable **Time-Based One-Time Password (TOTP) generator** implemented in Go. It allows you to generate and optionally validate TOTP codes using various hashing algorithms, code lengths, and time steps, all configurable via command-line flags.

---

## Features

* **Configurable Hashing Algorithm:** Supports SHA-1, SHA-256, and SHA-512. (SHA-1 is the standard for most TOTP applications, as per RFC 6238).
* **Adjustable Digits:** Generate OTPs with 6, 8, or more digits.
* **Customizable Time Step:** Set the validity period for the OTP (e.g., 30 seconds, 60 seconds).
* **Command-Line Interface:** All parameters are easily controlled via flags.
* **Validation Functionality:** Includes a basic validation feature to check if a given OTP is valid against a secret and parameters.

## Usage

The `totp-generator` supports several command-line flags for configuration.

### Generating an OTP

To generate a TOTP, you **must** provide the secret key using the `-secret` flag.

```bash
./totp-generator -secret "MYSUPERSECRETLONGENOUGHKEY"
