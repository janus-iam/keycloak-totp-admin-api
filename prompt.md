I want you to create an extension for keycloak which exposes admin api endpoints to manage TOTP credentials.


All endpoints follow the pattern:

```
/admin/realms/{realm}/authentication/totp/{operation}/{user-id}
```

### 1. 🔐 Generate TOTP Secret

**GET** `/generate`
Generates a TOTP secret and base64-encoded QR code.

**Response**:

```json
{
  "encodedSecret": "OFIWESBQGBLFG432HB5G6TTLIVIEGU2O",
  "qrCode": "iVBORw0KGgoAAAANSUhEUg..."
}
```

---

### 2. 📝 Register TOTP Credential

**POST** `/register`
Registers a TOTP credential for the user.

**Request Body**:

```json
{
  "deviceName": "MyDevice",
  "encodedSecret": "OFIWESBQGBLFG432HB5G6TTLIVIEGU2O",
  "initialCode": "128356",
  "overwrite": true
}
```

**Response**:

```json
{
  "message": "OTP credential registered"
}
```

---

### 3. ✅ Verify TOTP Code

**POST** `/verify`
Validates a user-supplied TOTP code.

**Request Body**:

```json
{
  "deviceName": "MyDevice",
  "code": "128356"
}
```

**Response**:

```json
{
  "message": "OTP code is valid"
}
```

### 4. ✅ Remove TOTP Code

**POST** `/remove`
Remove User TOTP code by deviceName.

**Request Body**:

```json
{
  "deviceName": "MyDevice"
}
```

**Response**:

```json
{
  "message": "OTP credential removed"
}
```

### 5. ✅ Get User TOTP Credential

**Get** `/get-totp-credentials`
Get all user totp credential.

**Response**:

```json
{
  "deviceName":[
     "MyDevice"
  ]
}
```