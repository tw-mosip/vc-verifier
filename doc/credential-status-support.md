## Support for Credential Status during verification of Verifiable Credential

This document provides a comprehensive overview to check credentual status for a Verifiable Credential (VC) as per 
[W3C StatusList2021 specification](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry).

### Supported Credential Formats
- Credential status is supported only for `ldp_vc` credential format.

### Steps Involved
1. Verify the credential as per existing process for the specific credential format.
2. Check the credential status as per W3C StatusList2021 specification.
   - If the credential format is `ldp_vc`, follow the steps mentioned below to check the credential status.
     - Fetch the status list credential from the `credentialStatus` property of the VC.
     - Validate and Verify the status list credential.
     - Decode the bitstring from the status list credential.
     - Check the bit at the index specified in the `statusListIndex` property of the VC.
     - If the bit is set to 0, the credential is valid. If it is more than 0 the credential is not valid.
   - For other credential formats, throw `UnsupportedOperationException`.

###  Sequence diagram - To check credential status for `ldp_vc` credential format VC

```mermaid
sequenceDiagram
    participant Wallet
    participant CredentialsVerifier
    participant CredentialVerifierFactory
    participant LdpVerifiableCredential
    participant LdpStatusChecker
    
    Wallet->>CredentialsVerifier: getCredentialStatus(credential, format, statusPurposeList)
    CredentialsVerifier->>CredentialVerifierFactory: Create instance of VerifiableCredential
    CredentialVerifierFactory->>LdpVerifiableCredential: Create LdpVerifiableCredential instance
    CredentialsVerifier->>LdpVerifiableCredential: checkStatus(credential, statusPurposeList)
    LdpVerifiableCredential->>LdpStatusChecker: getStatuses(credential, statusPurposeList)
    
    LdpStatusChecker->>LdpStatusChecker: Parse VC JSON
    alt No credentialStatus field
        LdpStatusChecker-->>LdpVerifiableCredential: Return empty status map
    else credentialStatus field present
        LdpStatusChecker->>LdpStatusChecker: Filter entries by statusPurpose
        alt No matching entries
            LdpStatusChecker-->>LdpVerifiableCredential: Return empty status map
        else Matching entries found
            loop For each entry
                LdpStatusChecker->>LdpStatusChecker: Validate credentialStatus entry
                LdpStatusChecker->>LdpStatusChecker: Fetch and validate status list VC
                LdpStatusChecker->>LdpStatusChecker: Compute status result
                alt Status check fails
                    LdpStatusChecker-->>LdpVerifiableCredential: Add failure result
                else Status check succeeds
                    LdpStatusChecker-->>LdpVerifiableCredential: Add success result
                end
            end
        end
    end
    LdpStatusChecker-->>LdpVerifiableCredential: Return status results
    LdpVerifiableCredential-->>CredentialsVerifier: Return status results
    CredentialsVerifier-->>Wallet: Return status results
```

