import ActiveChainVerifier

guard activechain_verifier_abi_revision() == 1,
      activechain_verifier_schema_revision() == 1,
      activechain_verifier_protocol_revision() == 1 else {
    fatalError("incompatible ActiveChain verifier")
}

let domain = Array("swiftledger.audit.v1".utf8)
let digest = [UInt8](repeating: 0, count: 32)
var reference = [UInt8](repeating: 0, count: 48)
var statementLength: UInt32 = 0
let queryCode = domain.withUnsafeBufferPointer { domainBuffer in
    digest.withUnsafeBufferPointer { digestBuffer in
        reference.withUnsafeMutableBufferPointer { referenceBuffer in
            activechain_anchor_statement_v1(
                domainBuffer.baseAddress,
                UInt32(domainBuffer.count),
                digestBuffer.baseAddress,
                nil,
                0,
                &statementLength,
                referenceBuffer.baseAddress
            )
        }
    }
}
guard queryCode == ACTIVECHAIN_VERIFY_BUFFER_TOO_SMALL, statementLength > 0 else {
    fatalError("anchor statement size query failed")
}
var statement = [UInt8](repeating: 0, count: Int(statementLength))
let statementCode = domain.withUnsafeBufferPointer { domainBuffer in
    digest.withUnsafeBufferPointer { digestBuffer in
        statement.withUnsafeMutableBufferPointer { statementBuffer in
            reference.withUnsafeMutableBufferPointer { referenceBuffer in
                activechain_anchor_statement_v1(
                    domainBuffer.baseAddress,
                    UInt32(domainBuffer.count),
                    digestBuffer.baseAddress,
                    statementBuffer.baseAddress,
                    UInt32(statementBuffer.count),
                    &statementLength,
                    referenceBuffer.baseAddress
                )
            }
        }
    }
}
guard statementCode == ACTIVECHAIN_VERIFY_OK else {
    fatalError("anchor statement encoding failed")
}
