pragma solidity ^0.4.11;
import "./imported/bytesutils.sol";
import "./ECMath.sol";

library tlsnutils{
    
    using bytesutils for *;

    /*
     * @dev Returns the complete conversation part of one peer (all generator records).
     * @param proof The proof.
     * @param conversation_part 0 = Requester(Client), 1 = Generator(Server).
     * @return The response as a bytestring.
    */
    function getConversationPart(bytes memory proof, bytes1 conversation_part) private returns(bytes){
        bytes memory response = "";
        uint16 readPos = 96;
        // Skipping the certificate chain
        readPos += uint16(proof[26])+256*uint16(proof[27]);
        bytes1 generator_originated;
        // Parse one record after another ( i < num_proof_nodes )
        for(uint16 i = 0; i < uint16(proof[6])+256*uint16(proof[7]); i++){

            // Assume the request is in the first record
            bytes2 len_record; // Length of the record
            assembly { len_record := mload(add(proof,add(readPos,33))) }
            
            uint16 tmplen = uint16(len_record[0])+256*uint16(len_record[1]);

            generator_originated = proof[readPos+3];

            // Skip node, type, content len and generator info
            readPos += 4;

            if(generator_originated == conversation_part){
                var chunk = proof.toSlice(readPos).truncate(tmplen); 
                response = response.toSlice().concat(chunk);
            }
            readPos += tmplen + 16;              
        } 
        return response;
    }



    /*
     * @dev Returns the complete request (all requester records).
     * @param proof The proof.
     * @return The request as a bytestring.
    */
    function getRequest(bytes memory proof) internal returns(bytes){
        return getConversationPart(proof, 0);
    }


    /*
     * @dev Returns the complete response (all generator records).
     * @param proof The proof.
     * @return The response as a bytestring.
    */
    function getResponse(bytes memory proof) internal returns(bytes){
        return getConversationPart(proof, 1);
    }



    /*
     * @dev Returns the HTTP body.
     * @param proof The proof.
     * @return The HTTP body in case the request was valid. (200 OK) 
    */
    function getHTTPBody(bytes memory proof) internal returns(bytes){
        bytes memory response = getResponse(proof);
        bytesutils.slice memory code = response.toSlice().truncate(15);
        require(code.equals("HTTP/1.1 200 OK".toSlice()));
        bytesutils.slice memory body = response.toSlice().find("\r\n\r\n".toSlice());
        body.addOffset(4);
        return body.toBytes();  
    }

    
    /*
     * @dev Returns HTTP Host inside the request
     * @param proof The proof.
     * @return The Host as a bytestring.
    */
    function getHost(bytes memory proof) internal returns(bytes){
        bytesutils.slice memory request = getRequest(proof).toSlice();
        // Search in Headers
        request = request.split("\r\n\r\n".toSlice());
        // Find host header
        request.find("Host:".toSlice());
        request.addOffset(5);
        // Until newline
        request = request.split("\r\n".toSlice());
        while(request.startsWith(" ".toSlice())){
            request.addOffset(1);
        }
		require(request.len() > 0);
        return request.toBytes();
    }

    /*
     * @dev Returns the requested URL for HTTP
     * @param proof The proof.
     * @return The request as a bytestring. Empty string on error.
    */
    function getHTTPRequestURL(bytes memory proof) internal returns(bytes){
        bytes memory request = getRequest(proof);
        bytesutils.slice memory slice = request.toSlice();
        bytesutils.slice memory delim = " ".toSlice();
        // Check the method is GET
        bytesutils.slice memory method = slice.split(delim);
        require(method.equals("GET".toSlice()));
        // Return the URL
        return slice.split(delim).toBytes();
    }

    /*
     * @dev Verify a proof signed by tls-n.org.
     * @param proof The proof.
     * @return True iff valid.
    */
	function verifyProof(bytes memory proof) returns(bool) {
		uint256 qx = 0x0de2583dc1b70c4d17936f6ca4d2a07aa2aba06b76a97e60e62af286adc1cc09; //public key x-coordinate signer
		uint256 qy = 0x68ba8822c94e79903406a002f4bc6a982d1b473f109debb2aa020c66f642144a; //public key y-coordinate signer
		return verifyProof(proof, qx, qy);
	}

    /*
     * @dev Verify a proof signed by the specified key.
     * @param proof The proof.
     * @return True iff valid.
    */
	function verifyProof(bytes memory proof, uint256 qx, uint256 qy) returns(bool) {
		bytes32 m; // Evidence Hash in bytes32
		uint256 e; // Evidence Hash in uint256
		uint256 sig_r; //signature parameter
		uint256 sig_s; //signature parameter

		// Returns ECC signature parts and the evidence hash
		(sig_r, sig_s, m) = parseProof(proof);

		// Convert evidence hash to uint
		e = uint256(m);

		// Verify signature
		return ECMath.ecdsaverify(qx, qy, e, sig_r, sig_s);

	}

    /*
     * @dev Parses the provided proof and returns the signature parts and the evidence hash.
	 * For 64-byte ECC proofs with SHA256.
     * @param proof The proof.
     * @return sig_r, sig_s: signature parts and hashchain: the final evidence hash.
    */
  function parseProof(bytes memory proof) returns(uint256 sig_r, uint256 sig_s, bytes32 hashchain) {

      uint16 readPos = 0; // Initialize index in proof bytes array
      bytes16 times; // Contains Timestamps for signature validation
	  bytes2 len_record; // Length of the record
	  bytes1 generator_originated; // Boolean whether originated by generator
	  bytes memory chunk; // One chunk for hashing
	  bytes16 saltsecret; // Salt secret from proof

      // Parse times
      assembly {
        times := mload(add(proof, 40))
      }
      readPos += 32; //update readPos, skip parameters

    assembly {
        sig_r := mload(add(proof,64))
        sig_s := mload(add(proof,96))
	    readPos := add(readPos, 64)
    }

      // Skipping the certificate chain
      readPos += uint16(proof[26])+256*uint16(proof[27]);

      // Parse one record after another ( i < num_proof_nodes )
	  for(uint16 i = 0; i < uint16(proof[6])+256*uint16(proof[7]); i++){
			// Get the Record length as a byte array
			assembly { len_record := mload(add(proof,add(readPos,33))) }
			// Convert the record length into a number
			uint16 tmplen = uint16(len_record[0])+256*uint16(len_record[1]);
			// Parse generator information
			generator_originated = proof[readPos+3];
			// Update readPos
			readPos += 4; 
			// Set chunk pointer
			assembly { chunk := add(proof,readPos) }
			// Set length of chunks 
			assembly { mstore(chunk, tmplen) }
			// Load saltsecret
			assembly { saltsecret := mload(add(proof,add(readPos,add(tmplen,32)))) }
			// Root hash
			bytes32 hash = sha256(saltsecret,chunk,uint8(0),len_record,generator_originated);
			// Hash chain
			if(i == 0){
				hashchain = sha256(uint8(1),hash);
			}else{
				hashchain = sha256(uint8(1),hashchain,hash);
			}
			// Jump over record and salt secret
			readPos += tmplen + 16; 
		}
		// Compute Evidence Hash
		// Load chunk size and salt size 
		bytes4 test; // Temporarily contains salt size and chunk size 
		assembly { test := mload(add(proof,34)) } 
		// Compute final hash chain
		hashchain = sha256(hashchain, times, test, 0x04000000);
    }
}
