#include "generator.hpp"

#include <fstream>
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
namespace test {
namespace {
///////////////////////////////////////////////////////////////////////////////

const unsigned char BinaryShort[] = {
    0x68, 0x40, 0x4c, 0x76, 0x37, 0x71, 0x88, 0x14,
    0x3a, 0xe9, 0x67, 0x3f, 0x94, 0x13, 0xda, 0xdd,
    0x03, 0x80, 0x9d, 0x31, 0x00, 0xff, 0xd7, 0x78,
    0xba, 0xac, 0x90, 0xf0, 0xa3, 0x0e, 0xc0, 0xca,
    0x71, 0x4f, 0xe4, 0x23, 0x48, 0xf2, 0x3e, 0x5d,
    0x85, 0x63, 0xfb, 0x62, 0x67, 0x08, 0xf5, 0x77,
    0x00, 0x25, 0xf6, 0x2c, 0x74, 0x10, 0x77, 0x59,
    0xdf, 0xb2, 0x18
};

// with many possible null bytes in the middle
const unsigned char BinaryLong[] = {
    0xf3, 0x1b, 0x00, 0xa1, 0x98, 0xbf, 0xd0, 0xe9,
    0xf6, 0x2a, 0xea, 0x28, 0xe0, 0x53, 0xc7, 0x69,
    0xee, 0xdf, 0x81, 0x00, 0x00, 0xb0, 0x67, 0x00,
    0x67, 0xf5, 0xf1, 0xec, 0xff, 0x8e, 0x8d, 0xfe,
    0xe3, 0x5a, 0xc8, 0xb2, 0xd3, 0xdc, 0xe6, 0x9d,
    0xa2, 0x1f, 0x4e, 0xa6, 0x9b, 0xb2, 0xf0, 0xb8,
    0x89, 0xa6, 0x4d, 0xb8, 0xe5, 0x88, 0x22, 0xa4,
    0xc9, 0xec, 0x69, 0xc7, 0x8e, 0x2c, 0x24, 0x04,
    0x29, 0x07, 0xb9, 0x00, 0x32, 0x21, 0x12, 0xab,
    0x18, 0x9a, 0xaf, 0xdb, 0xdb, 0x75, 0x77, 0xd0,
    0x23, 0x37, 0xa3, 0xa9, 0xe6, 0xd0, 0xe3, 0x35,
    0x13, 0x2b, 0x24, 0xf5, 0xe6, 0xe9, 0x74, 0x5f,
    0xb7, 0x08, 0x33, 0x97, 0xb1, 0x75, 0xf9, 0x1c,
    0xea, 0x3a, 0xcb, 0xdf, 0x58, 0x73, 0x35, 0x9a,
    0x6a, 0x12, 0xc1, 0x07, 0x0a, 0x59, 0x40, 0xfa,
    0xb4, 0xb7, 0xc8, 0x6d, 0xab, 0x63, 0x00, 0x8b,
};

// signature of long_text with the private key and sha1
const unsigned char SignatureSha1[] = {
    0xb9, 0x33, 0x2d, 0xd3, 0xea, 0xd2, 0xbf, 0x6d,
    0x98, 0x31, 0xe0, 0x16, 0xf3, 0xf1, 0x4a, 0x47,
    0x37, 0x56, 0x85, 0x74, 0x7d, 0x08, 0x03, 0x88,
    0x21, 0x97, 0xb4, 0x1c, 0x30, 0xc7, 0x68, 0x1c,
    0x23, 0x67, 0xf4, 0x90, 0x9b, 0x2d, 0xb6, 0x8b,
    0xcd, 0x4b, 0xb3, 0x29, 0x66, 0xcd, 0x5b, 0xc6,
    0xce, 0x6d, 0xcc, 0x0d, 0xe7, 0xc8, 0x08, 0x3e,
    0x31, 0x0f, 0xb4, 0x48, 0x43, 0x6d, 0x70, 0x93,
    0xc1, 0x53, 0xed, 0x20, 0x90, 0xfc, 0x2d, 0x90,
    0x8f, 0xa5, 0x1f, 0x1f, 0xb7, 0x5b, 0xf1, 0x1a,
    0x28, 0x80, 0x5c, 0xc4, 0xb3, 0xf6, 0x5c, 0x4e,
    0xd3, 0xc7, 0xb9, 0x12, 0x56, 0x36, 0x67, 0x70,
    0xd5, 0x81, 0xf4, 0x3c, 0x21, 0xa5, 0xec, 0xd0,
    0xfd, 0xff, 0x5b, 0x28, 0xf3, 0xaf, 0x34, 0x30,
    0x2e, 0xb5, 0xee, 0x0d, 0xf1, 0x04, 0x67, 0x09,
    0x97, 0xc8, 0xab, 0xfb, 0xec, 0x95, 0xd1, 0xff,
    0x6a, 0xa5, 0x0b, 0xce, 0xbe, 0xb2, 0x56, 0x18,
    0x26, 0xb3, 0x60, 0x3b, 0x4a, 0xd7, 0x64, 0xbb,
    0xd8, 0xa2, 0x1a, 0x5d, 0x06, 0x9c, 0x39, 0x73,
    0x87, 0x76, 0xde, 0x54, 0xc0, 0xfe, 0x3b, 0xbc,
    0xff, 0x69, 0x6d, 0xde, 0x1a, 0x67, 0x10, 0x09,
    0x33, 0xda, 0x34, 0xa0, 0x8f, 0x88, 0xf0, 0x62,
    0x2e, 0x63, 0x26, 0x4f, 0xea, 0xd0, 0x44, 0xa4,
    0x36, 0xe5, 0x80, 0xbc, 0x2d, 0xf5, 0xed, 0xe5,
    0xaf, 0x21, 0x03, 0x1d, 0x95, 0x86, 0x4b, 0x41,
    0x88, 0xcf, 0xc0, 0x55, 0xfc, 0x2d, 0x83, 0xb7,
    0x80, 0x94, 0x6b, 0x93, 0xe5, 0x1a, 0x3d, 0x48,
    0xdb, 0xe4, 0xa7, 0xaf, 0xe9, 0x22, 0x64, 0xdd,
    0x0d, 0x49, 0x5d, 0xc3, 0x0d, 0x56, 0x39, 0xf9,
    0xc5, 0xbc, 0x0a, 0xf4, 0xb8, 0xe2, 0x48, 0xd9,
    0x1a, 0x62, 0xec, 0x3f, 0xf5, 0x15, 0x30, 0x31,
    0xae, 0x41, 0xea, 0x15, 0xab, 0xaf, 0x3f, 0x44,
};
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////

void
dump_to_file(const buffer_t& data, const char* filename) {
    std::fstream f(filename, std::fstream::out | std::fstream::binary);
    f << data;
}

const char*
short_text() {
    return "mbedtls cryptography";
}

const char*
long_text() {
    return "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
        " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        " Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris"
        " nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in"
        " reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
        " Excepteur sint occaecat cupidatat non proident,"
        " sunt in culpa qui officia deserunt mollit anim id est laborum.";
}

buffer_t
short_binary() {
    constexpr size_t length = sizeof(BinaryShort);
    return buffer_t(reinterpret_cast<const char*>(BinaryShort), length);
}

buffer_t
long_binary() {
    constexpr size_t length = sizeof(BinaryLong);
    return buffer_t(reinterpret_cast<const char*>(BinaryLong), length);
}

buffer_t
sample_private_key() {
    buffer_t k(R"xx(-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA4EjipWXxJPtz0KYDz5+fYWkGly7ieRJ2Zql9BkaIOjz3By/K
L+jkYbUIwOQ+jM+FComsII9Y6309Db74sfwtykJoyUGTvMfHsZ/0VmgWOwPcUZ6v
nw45D6YuOzoTRLSErR/Vd2EIjNlhYlHg8cy6j/M7IqlCrBfz5xdTVYkqU+c0dZ/z
7FbbTgCA/9VjCPH3NjtJ34OWYY4HIok+ml8ervlZkiBEIRW/rKiOUMBKy4fgGeWZ
ZBsMaf4wkO8O8fBvfT1CZvxsQnAzN/boRm8t00GT5VmyHsgEHU3rKIf31yA834x5
WqgOl7WV6GvGnrG9sWOH3/rJClxTadG3HiIarQIDAQABAoIBAHHF51sZzGsDN2vn
W1WOVo5WdaZpfS8Ho5JOdgKh8ucAGBvILVuCW6AI8qjO38AUYRvIXM2jierje/4m
GwhGsX/BkmBNaMFB4tYDGzJd2LEVM0UgJ1ybHW0H0rnuqumWXRtpY6MMUQcKGrGC
cYaXYSg2rY/WpuCfwfU/SuHAE/28/xudngyiJQ0haabYnYPGfIdCgGMarBFLNN9S
95BhbAMavL+5D2E9p/lYAHih3K8UtYcjwJ8E71NiqBl2+fNYFDSVjB+KhJS07k4l
1yEnr9hwXPn/04g35oA7XBKOy2JgjN7ylP69XgZsJczpV02OwqJktqEKwt1kt499
wb0m3yECgYEA9bqXNPciOi29I1pIzhYTIvSQF6Xfr0mW3I6jlUy4dbqdJBj6zI6F
23KZITUi1N5gBeFQfiVvFkxrtTU69Cr/yVsLHlyEXdOKRZR6lUge+PYaeNULL3JP
jSBL4kB417qBYugTCWn4cgm1UbbfI7aHXcvlDyX6pk5Gz4ly0UtvAqkCgYEA6ajV
H/8VbgYlwmmFvbgnolY0mt53jAtVsAGbJTcwZOTwLlbPzJ0MvI3nCAMWM1lfyJKm
5W2trQlEMCe1tfX/OrM6KrdqR4esk1fSASVVKmH1xhJPcCdlgjD+lSmNU+0vv4EX
sFIfxwggznwUm8T3a2ZRs4VjavCySb6WKWr8XmUCgYB9MdnEBH2NwqvwjRk21oxd
bNjVE4/JkOap7IpvkK0SXkedkpSFD8AnNFXMU3QxnDK0DD2kZ5IXfEwMANjOefHk
NtyNVXmjDBoQpTtnP114XnrSQUj3nXfmYSQIW+y1jLJLIA5C55jLESMuRMufOGnz
YeSMOT9g59Sv/ElhVNt0MQKBgAsWjfaUvkmYVRZit4wHPyo++QQYZofoycouaVRc
yBkhnBw21mmZUk9oVHxW2Sjapub3vp/IkqNRe0DlwYO/BrucYbhBN/PpBlF/q2GO
ifoW5/jcSZTC6dhBxvMBI8nFyaxGzf76BrQFOLlTvg6eTDd2hY4FWHBst6k0OCAD
CbLZAoGAEnJrPPR7CctuWHkWQeDcP38CmGkPYWPHWBOEf6GpSazKXPBXeSa+nNbt
0k+n2u+8kymX+iYWsGVdGv3RKXFIzI4R9408SR5OZI1jAF6BZweYaE2RcVaferB3
wyeaiI5gpvmQb/KVreVvagVNR7TJHO6ybG/rc2ssfVIAXmKHtOI=
-----END RSA PRIVATE KEY-----)xx");

    k.push_back('\0');
    return k;
}

buffer_t
sample_private_key_password() {
    buffer_t k(R"xx( -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,142902F647920CE4B7AE3C2913FDFA10

nagu3l0U8ExoFvhCb8Te4nzsMGnBjdLUmfOm3abYhZLF7nTUv7EHmRGvJJnyHXjp
roBGiX4iii4FuUyAea1pIJNAi64f6V5XwSN5N+uEjcoHX55gl/o+kaGovXkDWq3A
xx4WqTeW0Jlr8Z1sx35NUrKf87h3JNRGqMK1cX+E7tmnhUx6orHBL+1ovTIPZ7LW
0fZHNHUl3tC87TCeHUgUvIZGWPSR3e9tbzfIzV6t68oXe8atvm2MAnRPZnYi8/7c
dSe77fTo/9rGVjhtg+wLmCqC9mOYOFIVORERcVMK/V2BZe1hsWcjmjFeg+DnaE6s
eCAV60S/QNkvQlWi/AdF5PRz9hHq8mQbhrPbKppabBQyrVOPytEFy76a7966t62Q
qtCGAC7aTVw0GKa9KmiD0CYA6aixVtw0+lP4jHquotGNZtletBwme2k/MsckmPK0
bsf6033SaUKD8uiW0JHQj26JgEgKZx7ZAIhKqEsRtLp0/YEw3kQQBEewBxEvmCE/
fFpGrE2joB+MvLoVaUv+4Vy2Er4A+C0KBCna8hwEV9yhrE5D4Ny5yp6yIvy9SsN4
7Nvdg25h7l6o6d0npW6W/w272skb2BlID/EEtwSCmUZLDCRN0chH99t+5OgDcA1N
qKXjnJpU5uqDzWuVi790Va5dfUE2oh/YSJShlstne4/xFlhHtCPlFPYcnFoJwrjg
KqahkEAj55qz9W7RU1uTEDt8CGTuPsWMIBsN+n5BDoeM0ZsF3ZcJ1zSXsyVuiYVs
NzxFlXFg7ZICeLkUFM8QnfkDXo6JLkqUX/mDpG2xZfi41CpgX/k9xW+dTRnHRY2x
vY0buJijF3GYgzdYHbicT/vdXud0HknN/31kf9M/pesCpIOLYliz91rcuO/6Afcw
TpUbneaMjWcHdCA4zl54x9HypE9xlbnM0gTiVqS2j8AC4cwVJS7Tjx5jQItojjxh
tFE5zcJyxp0U9lVOUAGRrJ76C8zZi4Qp2HEc4o+FCQHDrZP6pfAF9q0a0Jrm4rYV
H2a21Qxij7NHACP4r8/iQEDam5N5aZhQ8cd07+1F48l18iZGBd0FW0wRI2vVyyNG
hrgK+AI5KVNuYtGzuTI59HMdJ29VK6u3kBV8pc7Haa0pPiAeW559oxQI9NOBA5Hb
zon80m5yBKvNGUr6mgiFWVvZrtwuDtWo9rGW7Zstpe7QOK3HjidpJMvncDtumb2I
d+vWVody3ZnMrXqLyNABI0EsgMQzxtUGnTZYBRHDd+unzB4FTBUe6j5z/oR9iQNo
RhfLJQ8DonXiYxeZyeDs8Ich53esK+1BzjO2TbMEOK4UG37L4il7+t4X9kpkZebU
f/YCdO3rxvJqv2CeTxqJfYIg++js18Q0aZltNmX/3fw8D7RNCWZzmOJ6S5qwOlNZ
XTuhmduauf2SGodpU4emhZDUkHJKAmYAsFg/BL0K09lLogHniNmYDoi+I26Dbte3
Et0P926W1pf7lVnPoj8w2C7VWGOkY/o/bGZFYWEe00jTvZGo2cO0uYI/ivfSFSoc
RAQ8ivI/WxzhB6YT3yG4jf/oPAMiC8WZEYhIqQd/yfZRRCGaGvjMnw4jYG+vVy+D
-----END RSA PRIVATE KEY-----)xx");

    k.push_back('\0');
    return k;
}

buffer_t
sample_public_key() {
    buffer_t k(R"xx(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4EjipWXxJPtz0KYDz5+f
YWkGly7ieRJ2Zql9BkaIOjz3By/KL+jkYbUIwOQ+jM+FComsII9Y6309Db74sfwt
ykJoyUGTvMfHsZ/0VmgWOwPcUZ6vnw45D6YuOzoTRLSErR/Vd2EIjNlhYlHg8cy6
j/M7IqlCrBfz5xdTVYkqU+c0dZ/z7FbbTgCA/9VjCPH3NjtJ34OWYY4HIok+ml8e
rvlZkiBEIRW/rKiOUMBKy4fgGeWZZBsMaf4wkO8O8fBvfT1CZvxsQnAzN/boRm8t
00GT5VmyHsgEHU3rKIf31yA834x5WqgOl7WV6GvGnrG9sWOH3/rJClxTadG3HiIa
rQIDAQAB
-----END PUBLIC KEY-----)xx");

    k.push_back('\0');
    return k;
}

buffer_t
long_text_signature() {
    constexpr size_t length = sizeof(SignatureSha1);
    return buffer_t(reinterpret_cast<const char*>(SignatureSha1), length);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace test
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
