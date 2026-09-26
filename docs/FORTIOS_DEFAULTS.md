# FortiOS Version-Aware Defaults Engine

## Architectural Principle

The FortiGate Security Analyzer maintains three separate, un-merged layers of truth:

1. **Explicit Configuration Facts**: Raw tokens parsed directly from configuration input without alteration.
2. **Documented Default Inferences**: Formally verified, branch-specific FortiOS defaults applied solely when rigorous gating criteria are met.
3. **Technical Interpretations**: Downstream assessment where explicit configuration always overrides default inferences.

> [!IMPORTANT]
> This defaults engine is **intentionally conservative and incomplete**.
> - Defaults are **never** inferred across continuous or unverified version boundaries.
> - Defaults are **never** inferred for partial configurations or configurations with unknown/unverified FortiOS versions.
> - An omitted field in partial input means **"not observed in supplied input"**, not default/disabled/insecure.
> - Explicit configuration values **always win**.

---

## Gating Requirements for Default Inferences

A default inference is applied if and only if **all** of the following conditions are satisfied:

1. **Explicit Value Absent**: The configuration does not contain an explicit setting for the field.
2. **Input Completeness Verified**: The input classification is `LIKELY_FULL_BACKUP` (partial configurations do not infer defaults from field omission).
3. **Section Presence Verified**: The parent configuration section was observed in the raw input text.
4. **FortiOS Version Detected**: A valid `#config-version=` header was parsed with explicit `major` and `minor` numbers.
5. **Branch Individually Verified**: The `(major, minor)` branch has been individually verified against official Fortinet CLI documentation.

If any condition fails, the engine returns an explainable status:
- `EXPLICIT_VALUE`
- `DOCUMENTED_DEFAULT_APPLIED`
- `DEFAULT_NOT_APPLICABLE`
- `INPUT_SCOPE_INSUFFICIENT`
- `SECTION_NOT_SUPPLIED`
- `VERSION_UNKNOWN`
- `UNSUPPORTED_VERSION`

---

## Officially Verified Rules Registry

### 1. `system_ntp.type`
- **Rule ID**: `system_ntp.type`
- **Configuration Path**: `config system ntp`
- **Field**: `type`
- **Verified FortiOS Branches**: `7.0`, `7.2`, `7.4`
- **Default Value**: `fortiguard`
- **Official Documentation Sources**:
  - FortiOS 7.0 CLI Reference: `config system ntp` -> `set type {fortiguard | custom}` (Default: `fortiguard`).
  - FortiOS 7.2 CLI Reference: `config system ntp` -> `set type {fortiguard | custom}` (Default: `fortiguard`).
  - FortiOS 7.4 CLI Reference: `config system ntp` -> `set type {fortiguard | custom}` (Default: `fortiguard`).
- **Safety / Applicability**:
  - `config system ntp` section must be present with `ntpsync enable`.
  - When custom servers are omitted and `type` is not specified, FortiOS synchronizes with FortiGuard public NTP servers.

### 2. `system_global.admintimeout`
- **Rule ID**: `system_global.admintimeout`
- **Configuration Path**: `config system global`
- **Field**: `admintimeout`
- **Verified FortiOS Branches**: `7.0`, `7.2`, `7.4`
- **Default Value**: `5` (minutes)
- **Official Documentation Sources**:
  - FortiOS 7.0 CLI Reference: `config system global` -> `set admintimeout <integer>` (Default: `5`).
  - FortiOS 7.2 CLI Reference: `config system global` -> `set admintimeout <integer>` (Default: `5`).
  - FortiOS 7.4 CLI Reference: `config system global` -> `set admintimeout <integer>` (Default: `5`).
- **Safety / Applicability**:
  - `config system global` section must be present in a likely full backup.

### 3. `system_global.admin_sport`
- **Rule ID**: `system_global.admin_sport`
- **Configuration Path**: `config system global`
- **Field**: `admin-sport`
- **Verified FortiOS Branches**: `7.0`, `7.2`, `7.4`
- **Default Value**: `443`
- **Official Documentation Sources**:
  - FortiOS 7.0 CLI Reference: `config system global` -> `set admin-sport <integer>` (Default: `443`).
  - FortiOS 7.2 CLI Reference: `config system global` -> `set admin-sport <integer>` (Default: `443`).
  - FortiOS 7.4 CLI Reference: `config system global` -> `set admin-sport <integer>` (Default: `443`).
- **Safety / Applicability**:
  - `config system global` section must be present in a likely full backup.

### 4. `system_global.admin_port`
- **Rule ID**: `system_global.admin_port`
- **Configuration Path**: `config system global`
- **Field**: `admin-port`
- **Verified FortiOS Branches**: `7.0`, `7.2`, `7.4`
- **Default Value**: `80`
- **Official Documentation Sources**:
  - FortiOS 7.0 CLI Reference: `config system global` -> `set admin-port <integer>` (Default: `80`).
  - FortiOS 7.2 CLI Reference: `config system global` -> `set admin-port <integer>` (Default: `80`).
  - FortiOS 7.4 CLI Reference: `config system global` -> `set admin-port <integer>` (Default: `80`).
- **Safety / Applicability**:
  - `config system global` section must be present in a likely full backup.

### 5. `system_global.admin_ssh_port`
- **Rule ID**: `system_global.admin_ssh_port`
- **Configuration Path**: `config system global`
- **Field**: `admin-ssh-port`
- **Verified FortiOS Branches**: `7.0`, `7.2`, `7.4`
- **Default Value**: `22`
- **Official Documentation Sources**:
  - FortiOS 7.0 CLI Reference: `config system global` -> `set admin-ssh-port <integer>` (Default: `22`).
  - FortiOS 7.2 CLI Reference: `config system global` -> `set admin-ssh-port <integer>` (Default: `22`).
  - FortiOS 7.4 CLI Reference: `config system global` -> `set admin-ssh-port <integer>` (Default: `22`).
- **Safety / Applicability**:
  - `config system global` section must be present in a likely full backup.
