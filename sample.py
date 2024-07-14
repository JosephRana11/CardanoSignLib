# Sample Signed Data generated using a throwaway Wallet.

from index import verify_signed_data , extract_signed_address_from_signature_header , extract_payload_from_signature , extract_public_key_from_key

signed_data_sample = {
    "key": "a5010102583900433da06d5bfd038f6bcf5cf0085b94f6725e206129ef637f4fd704807b6952776da5b40b9fb08094275520dd811886dda350de9ce68cd49d03272006215820f5b05c2bdf302c5edbf26945ba55d5da7d5cfb06982f108efa4fba8fbd01734d",
    "signature": "845882a3012704583900433da06d5bfd038f6bcf5cf0085b94f6725e206129ef637f4fd704807b6952776da5b40b9fb08094275520dd811886dda350de9ce68cd49d6761646472657373583900433da06d5bfd038f6bcf5cf0085b94f6725e206129ef637f4fd704807b6952776da5b40b9fb08094275520dd811886dda350de9ce68cd49da166686173686564f4587c6163636f756e74203a2030303433336461303664356266643033386636626366356366303038356239346636373235653230363132396566363337663466643730343830376236393532373736646135623430623966623038303934323735353230646438313138383664646133353064653963653638636434396458404a69de1aa1b287816ce11bc444757dc478eceaa190c1dc46c578e2678a2c38914f71bd25adf75d9cbe6b8675bd9fa45f5b84d11f5f35b6b4d9b8d2108f84df0a"
}


# Returns True if the Signed Data is verified
print(verify_signed_data(hex_key=signed_data_sample['key'] , hex_signature=signed_data_sample['signature']))


# Returns the Address used to Sign the Data. ie Change Address , Stake Address etc
print(extract_signed_address_from_signature_header(hex_signature=signed_data_sample['signature']))


# Returns the Payload Data from the Signed Data Signature
print(extract_payload_from_signature(hex_signature=signed_data_sample['signature']))


# Returns public key from the Signed Data Key
print(extract_public_key_from_key(hex_key=signed_data_sample['key']))