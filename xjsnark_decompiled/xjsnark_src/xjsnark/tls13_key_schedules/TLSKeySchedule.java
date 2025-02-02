package xjsnark.tls13_key_schedules;

/*Generated by MPS */

import backend.auxTypes.UnsignedInteger;
import xjsnark.util_and_sha.Util;
import xjsnark.util_and_sha.SHA2;
import backend.structure.CircuitGenerator;
import xjsnark.aes_gcm.AES_GCM;
import backend.auxTypes.FieldElement;
import xjsnark.ecdhe.ECDHE;
import java.math.BigInteger;
import backend.auxTypes.SmartMemory;
import backend.auxTypes.Bit;
import backend.auxTypes.ConditionalScopeTracker;

public class TLSKeySchedule {

  // NOTATION is from https://eprint.iacr.org/2020/1044.pdf

  // This class contains functions that compute the different types of TLS1.3 Key Schedule
  // Input: 
  //   - handshake transcript
  //   - client's secrets (PSK and/or DHE share)
  //   - application data ciphertext
  // Output:
  //   - client's application traffic key
  //   - decryption of the applicaton data
  // .
  // This is done for 4 types of TLS 1.3 Key Schedule methods:
  //   - 0RTT
  //   - Baseline 1RTT
  //   - Shortcut 1RTT
  //   - Amortized Opening

  // The notation for all variables in this class is from:
  // https://eprint.iacr.org/2020/1044.pdf

  // The key dervation process for the different methods is in Figure 2




  // 0RTT method is a "session resumption" feature offered by TLS
  // where the client and server share a PSK (established in a previous session)
  // and the PSK can be used to send "early data" in the client's first message 
  // without a full handshake
  // See Figure 2 from https://eprint.iacr.org/2020/1044.pdf

  // The function broadly does the following steps:
  // (1) Using the PSK and transcript hashes, compute the binder
  // (2) Verify that it is equal to the REAL_BINDER from the transcript
  // (3) Now, compute the traffic keys and decrypt the ciphertext
  public static UnsignedInteger[] get0RTT(UnsignedInteger[] PSK, UnsignedInteger[] H_1, UnsignedInteger[] H_5, UnsignedInteger[] REAL_BINDER, UnsignedInteger[] dns_ciphertext) {

    UnsignedInteger[] ES = HKDF.hkdf_extract(Util.new_zero_array(32), PSK);

    UnsignedInteger[] dES = HKDF.quic_hkdf_expand_derive_secret(ES, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] BK = HKDF.quic_hkdf_expand_derive_secret(ES, "res binder", SHA2.hash_of_empty());

    UnsignedInteger[] fk_B = HKDF.quic_hkdf_expand_derive_secret(BK, "finished", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));

    // This is the binder derived by the purported PSK that was given as a witness to the circuit 
    UnsignedInteger[] derived_binder = HKDF.hmac(fk_B, H_5);

    // Verify that the derived binder is the same as the one from the transcript 
    Util.combine_8_into_256(REAL_BINDER).forceEqual(Util.combine_8_into_256(derived_binder));

    UnsignedInteger[] ETS = HKDF.quic_hkdf_expand_derive_secret(ES, "c e traffic", H_1);

    UnsignedInteger[] tk_early = HKDF.hkdf_expand_derive_tk(ETS, 16);
    UnsignedInteger[] iv_early = HKDF.hkdf_expand_derive_iv(ETS, 12);

    // decrypt the plaintext 
    UnsignedInteger[] dns_plaintext = AES_GCM.aes_gcm_decrypt(tk_early, iv_early, dns_ciphertext);
    return dns_plaintext;
  }

  // This is the baseline 1RTT handshake key derivation
  // Steps:
  // (1) Verify and derive the EC DHE secret
  // (2) Compute server handshake keys
  // (3) Decrypt the encrypted parts of CT3 (CH || SH || ServExt) to get TR3
  // (3) Hash TR3
  // (5) Derive client traffic keys and decrypt ciphertext

  // Inputs: DHE share and public points A and B
  // transcript hash H2 = Hash(CH || SH)
  // CH_SH - Transcript ClientHello || ServerHello and its length
  // ServExt_ct - the encrypted Server Extensions and its length
  // ServExt_tail_ct is the part of ServExt_ct that doesn't fit into a whole SHA block
  // appl_ct - the application data ciphertext
  public static UnsignedInteger[][] get1RTT(UnsignedInteger DHE_share, FieldElement Ax, FieldElement Ay, FieldElement Bx, FieldElement By, UnsignedInteger[] H2, UnsignedInteger[] CH_SH, UnsignedInteger CH_SH_len, UnsignedInteger[] ServExt_ct, UnsignedInteger ServExt_len, UnsignedInteger[] ServExt_tail_ct, UnsignedInteger[] appl_ct) {

    UnsignedInteger[] ES = HKDF.hkdf_extract(Util.new_zero_array(32), Util.new_zero_array(32));
    UnsignedInteger[] dES = HKDF.quic_hkdf_expand_derive_secret(ES, "derived", SHA2.hash_of_empty());

    // This function's goals: 
    // (1) Verify that G^sk = A where G is the generator of secp256 
    // (2) Compute B^sk to obtain the DHE secret 
    UnsignedInteger[] DHE = ECDHE.DHExchange(Ax.copy(), Ay.copy(), Bx.copy(), By.copy(), DHE_share.copy(256));

    UnsignedInteger[] HS = HKDF.hkdf_extract(dES, DHE);

    UnsignedInteger[] SHTS = HKDF.quic_hkdf_expand_derive_secret(HS, "s hs traffic", H2);

    // traffic key and iv for "server handshake" messages 
    UnsignedInteger[] tk_shs = HKDF.hkdf_expand_derive_tk(SHTS, 16);
    UnsignedInteger[] iv_shs = HKDF.hkdf_expand_derive_iv(SHTS, 12);

    UnsignedInteger[] dHS = HKDF.quic_hkdf_expand_derive_secret(HS, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] MS = HKDF.hkdf_extract(dHS, Util.new_zero_array(32));

    // Decrypt the server extensions with the server's handshake traffic keys 
    UnsignedInteger[] ServExt = AES_GCM.aes_gcm_decrypt(tk_shs, iv_shs, ServExt_ct);
    // Now, we need to decrypt the ServExt_tail. 
    // As we are using AES GCM, we need to find the exact block number that the tail starts at. 
    // One AES block = 16 bytes 
    UnsignedInteger gcm_block_number = UnsignedInteger.instantiateFrom(8, ServExt_len.div(UnsignedInteger.instantiateFrom(8, 64))).mul(UnsignedInteger.instantiateFrom(8, 4)).copy(8);

    // Returns the decryption starting at the GCM counter  
    UnsignedInteger[] Serv_Ext_tail = AES_GCM.aes_gcm_decrypt(tk_shs, iv_shs, ServExt_tail_ct, gcm_block_number.copy(8));

    // This transcript is CH || SH || ServExt 
    UnsignedInteger[] TR3 = Util.concat(CH_SH, ServExt);

    // As we don't know the true length of ServExt, the variable's size is a fixed upper bound 
    // However, we only require a hash of the true transcript, which is a prefix of the variable 
    // of length CH_SH_len + ServExt_len 
    UnsignedInteger[] H3 = SHA2.sha2_of_prefix(TR3, CH_SH_len.add(ServExt_len).copy(16), Serv_Ext_tail);

    UnsignedInteger[] CATS = HKDF.quic_hkdf_expand_derive_secret(MS, "c ap traffic", H3);

    UnsignedInteger[] tk_capp = HKDF.hkdf_expand_derive_tk(CATS, 16);
    UnsignedInteger[] iv_capp = HKDF.hkdf_expand_derive_iv(CATS, 12);

    UnsignedInteger[] dns_plaintext = AES_GCM.aes_gcm_decrypt(tk_capp, iv_capp, appl_ct);

    return new UnsignedInteger[][]{dns_plaintext, tk_capp, iv_capp};
  }




  // Implements the HS shortcut, where the client's witness is the HS secret 
  // Steps:
  // (1) Derive the server handshake key using the HS
  // (2) Use it to decrypt the ServerFinished value from the transcript - real_SF
  // (3) Derive the ServerFinished value using the purported HS - calculated_SF
  // (4) Verify that the two SF values are the same
  // (5) Using the HS, compute the client traffic keys and decrypt the ciphertext

  // HS - handshake secret
  // H2 - Hash(CH || SH)
  // ServExt - server extensions (the last 36 bytes of which are the ServerFinished ext)
  // ServExt_tail - the suffix of ServExt that does not fit in a whole SHA block

  // Transcript TR3 = ClientHello || ServerHello || ServExt
  // note that the final 36 bytes of TR3 contain the ServerFinished extension
  // TR7 is TR3 without the SF extension; that is, TR7 is TR3 without the last 36 bytes

  // SHA_H_Checkpoint - the H-state of SHA up to the last whole block of TR7
  public static UnsignedInteger[][] get1RTT_HS_new(UnsignedInteger[] HS, UnsignedInteger[] H2, UnsignedInteger TR3_len, UnsignedInteger CertVerify_len, UnsignedInteger[] CertVerify_ct_tail, UnsignedInteger[] ServerFinished_ct, UnsignedInteger CertVerify_tail_len, UnsignedInteger[] SHA_H_Checkpoint, UnsignedInteger[] appl_ct) {

    // INPUTS ARE CORRECT 









    // KEYS ARE CORRECT 

    UnsignedInteger[] SHTS = HKDF.hkdf_expand_derive_secret(HS, "s hs traffic", H2);

    // traffic key and iv for "server handshake" messages 
    UnsignedInteger[] tk_shs = HKDF.hkdf_expand_derive_tk(SHTS, 16);

    UnsignedInteger[] iv_shs = HKDF.hkdf_expand_derive_iv(SHTS, 12);

    // TODO: check if I can deep copy iv_shs last byte instead of xoring 2 times 
    // XOR original IV with the packet number (eiter 0x02 or 0x03) 
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x02)), 8);


    // TODO: consider switching to TR3_len directly 
    UnsignedInteger TR7_len = TR3_len.subtract(UnsignedInteger.instantiateFrom(8, 36)).copy(16);


    // TODO: understand if this can be done outside the circuit 
    // CertVerify = CertVerify_head || CertVerify_tail 
    UnsignedInteger CertVerify_head_len = CertVerify_len.subtract(CertVerify_tail_len).copy(16);

    // To decrypt the tail, we need to calculate the GCM counter block number 
    UnsignedInteger gcm_block_number = UnsignedInteger.instantiateFrom(8, CertVerify_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);
    // Additionally, the tail might not start perfectly at the start of a block 
    // That is, the length of head may not be a multiple of 16 
    UnsignedInteger offset = UnsignedInteger.instantiateFrom(8, CertVerify_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    // INPUT CORRETTI, OUTPUT SBAGLIATO 
    // This function decrypts the tail with the specific GCM block number and offset within the block (VERY CONVENIENT) 
    UnsignedInteger[] CertVerify_tail = AES_GCM.aes_gcm_decrypt_128bytes_middle(tk_shs, iv_shs, CertVerify_ct_tail, gcm_block_number.copy(8), offset.copy(8));
    for (int i = 0; i < CertVerify_tail.length; i++) {
      CircuitGenerator.__getActiveCircuitGenerator().__addDebugInstruction(CertVerify_tail[i], "CertVerify_tail");
    }

    // AES_128_GCM_SHA256 
    // xoring again for the next record layer 
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x02)), 8);
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x03)), 8);
    // Decrypting the FULL serverfinished (easy) 
    UnsignedInteger[] ServerFinished = AES_GCM.aes_gcm_decrypt(tk_shs, iv_shs, ServerFinished_ct);
    for (int i = 0; i < ServerFinished.length; i++) {
      CircuitGenerator.__getActiveCircuitGenerator().__addDebugInstruction(ServerFinished[i], "ServerFinished");
    }

    // This function calculates the hash of TR3 and TR7 where TR7 is TR3 without the last 36 characters 
    // starting with the SHA_H_Checkpoint provided as a checkpoint state of SHA that is common to both transcripts. 
    // The inputs are: 
    // - the checkpoint state 
    // - the length of TR3 and TR7 (the latter must be a prefix of the former) 
    // - the tail of TR3 (the part after the checkpoint) 
    // - the length of the tail up to TR3 
    // - the length of the tail up to TR7 
    UnsignedInteger[] Decrypted_Merged_tail = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{128}, 8);
    SmartMemory<UnsignedInteger> ServFinRam;
    ServFinRam = new SmartMemory(ServerFinished, UnsignedInteger.__getClassRef(), new Object[]{"8"});

    // TODO: is it necessary to pad with zeroes? 
    for (int i = 0; i < 128; i++) {
      {
        Bit bit_a0oc0xc = UnsignedInteger.instantiateFrom(8, i).isLessThan(CertVerify_tail_len).copy();
        boolean c_a0oc0xc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0oc0xc);
        if (c_a0oc0xc) {
          if (bit_a0oc0xc.getConstantValue()) {
            Decrypted_Merged_tail[i].assign(CertVerify_tail[i], 8);
          } else {
            {
              Bit bit_a0a0a0a2a0a66a57 = UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len).isLessThan(UnsignedInteger.instantiateFrom(8, 36)).copy();
              boolean c_a0a0a0a2a0a66a57 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0a2a0a66a57);
              if (c_a0a0a0a2a0a66a57) {
                if (bit_a0a0a0a2a0a66a57.getConstantValue()) {
                  Decrypted_Merged_tail[i].assign(ServFinRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len)), 8);
                } else {
                  {
                    Bit bit_a0a0a2a0a0a0a0c0a0oc0xc = UnsignedInteger.instantiateFrom(8, i).isGreaterThan(CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36))).copy();
                    boolean c_a0a0a2a0a0a0a0c0a0oc0xc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a2a0a0a0a0c0a0oc0xc);
                    if (c_a0a0a2a0a0a0a0c0a0oc0xc) {
                      if (bit_a0a0a2a0a0a0a0c0a0oc0xc.getConstantValue()) {
                        Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
                      } else {

                      }
                    } else {
                      ConditionalScopeTracker.pushMain();
                      ConditionalScopeTracker.push(bit_a0a0a2a0a0a0a0c0a0oc0xc);
                      Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

                      ConditionalScopeTracker.pop();

                      ConditionalScopeTracker.push(new Bit(true));

                      ConditionalScopeTracker.pop();
                      ConditionalScopeTracker.popMain();
                    }

                  }

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0a0a0a2a0a66a57);
                Decrypted_Merged_tail[i].assign(ServFinRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len)), 8);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                {
                  Bit bit_a0a0a0a0c0a0oc0xc_0 = UnsignedInteger.instantiateFrom(8, i).isGreaterThan(CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36))).copy();
                  boolean c_a0a0a0a0c0a0oc0xc_0 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0a0c0a0oc0xc_0);
                  if (c_a0a0a0a0c0a0oc0xc_0) {
                    if (bit_a0a0a0a0c0a0oc0xc_0.getConstantValue()) {
                      Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
                    } else {

                    }
                  } else {
                    ConditionalScopeTracker.pushMain();
                    ConditionalScopeTracker.push(bit_a0a0a0a0c0a0oc0xc_0);
                    Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

                    ConditionalScopeTracker.pop();

                    ConditionalScopeTracker.push(new Bit(true));

                    ConditionalScopeTracker.pop();
                    ConditionalScopeTracker.popMain();
                  }

                }
                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_a0oc0xc);
          Decrypted_Merged_tail[i].assign(CertVerify_tail[i], 8);

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          {
            Bit bit_a0a0a66a57_0 = UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len).isLessThan(UnsignedInteger.instantiateFrom(8, 36)).copy();
            boolean c_a0a0a66a57_0 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a66a57_0);
            if (c_a0a0a66a57_0) {
              if (bit_a0a0a66a57_0.getConstantValue()) {
                Decrypted_Merged_tail[i].assign(ServFinRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len)), 8);
              } else {
                {
                  Bit bit_a0a0a2a0a8a0c0a0oc0xc = UnsignedInteger.instantiateFrom(8, i).isGreaterThan(CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36))).copy();
                  boolean c_a0a0a2a0a8a0c0a0oc0xc = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a2a0a8a0c0a0oc0xc);
                  if (c_a0a0a2a0a8a0c0a0oc0xc) {
                    if (bit_a0a0a2a0a8a0c0a0oc0xc.getConstantValue()) {
                      Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
                    } else {

                    }
                  } else {
                    ConditionalScopeTracker.pushMain();
                    ConditionalScopeTracker.push(bit_a0a0a2a0a8a0c0a0oc0xc);
                    Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

                    ConditionalScopeTracker.pop();

                    ConditionalScopeTracker.push(new Bit(true));

                    ConditionalScopeTracker.pop();
                    ConditionalScopeTracker.popMain();
                  }

                }

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0a0a66a57_0);
              Decrypted_Merged_tail[i].assign(ServFinRam.read(UnsignedInteger.instantiateFrom(8, i).subtract(CertVerify_tail_len)), 8);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              {
                Bit bit_a0a0a0oc0xc_2 = UnsignedInteger.instantiateFrom(8, i).isGreaterThan(CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36))).copy();
                boolean c_a0a0a0oc0xc_2 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0oc0xc_2);
                if (c_a0a0a0oc0xc_2) {
                  if (bit_a0a0a0oc0xc_2.getConstantValue()) {
                    Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);
                  } else {

                  }
                } else {
                  ConditionalScopeTracker.pushMain();
                  ConditionalScopeTracker.push(bit_a0a0a0oc0xc_2);
                  Decrypted_Merged_tail[i].assign(UnsignedInteger.instantiateFrom(8, 0), 8);

                  ConditionalScopeTracker.pop();

                  ConditionalScopeTracker.push(new Bit(true));

                  ConditionalScopeTracker.pop();
                  ConditionalScopeTracker.popMain();
                }

              }
              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }
          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }
    UnsignedInteger Decrypted_Merged_tail_len = CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36)).copy(8);

    UnsignedInteger[][] H7_H3 = SHA2.double_sha_from_checkpoint(SHA_H_Checkpoint, TR3_len.copy(16), TR7_len.copy(16), Decrypted_Merged_tail, Decrypted_Merged_tail_len.copy(8), Decrypted_Merged_tail_len.subtract(UnsignedInteger.instantiateFrom(8, 36)).copy(8));

    UnsignedInteger[] H_7 = H7_H3[0];
    UnsignedInteger[] H_3 = H7_H3[1];
    // Derive the SF value from transcript hash H7 up to Certificate Verify 
    UnsignedInteger[] fk_S = HKDF.quic_hkdf_expand_derive_secret(SHTS, "finished", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    UnsignedInteger[] SF_calculated = HKDF.hmac(fk_S, H_7);
    for (int i = 0; i < SF_calculated.length; i++) {
      CircuitGenerator.__getActiveCircuitGenerator().__addDebugInstruction(SF_calculated[i], "SF Calculated");
    }


    UnsignedInteger[] SF_transcript = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    SmartMemory<UnsignedInteger> ServerFinished_RAM = new SmartMemory(ServerFinished, UnsignedInteger.__getClassRef(), new Object[]{"8"});
    for (int i = 0; i < 32; i++) {
      SF_transcript[i].assign(ServerFinished_RAM.read(UnsignedInteger.instantiateFrom(8, i).add(UnsignedInteger.instantiateFrom(8, 4))), 8);
    }
    for (int i = 0; i < SF_transcript.length; i++) {
      CircuitGenerator.__getActiveCircuitGenerator().__addDebugInstruction(SF_transcript[i], "SF_transcript:");
    }


    // Verify that the two SF values are identical 
    Util.combine_8_into_256(SF_calculated).forceEqual(Util.combine_8_into_256(SF_transcript));

    UnsignedInteger[] dHS = HKDF.hkdf_expand_derive_secret(HS, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] MS = HKDF.hkdf_extract(dHS, Util.new_zero_array(32));

    UnsignedInteger[] CATS = HKDF.hkdf_expand_derive_secret(MS, "c ap traffic", H_3);

    // client application traffic key, iv 
    UnsignedInteger[] tk_capp = HKDF.hkdf_expand_derive_tk(CATS, 16);
    UnsignedInteger[] iv_capp = HKDF.hkdf_expand_derive_iv(CATS, 12);

    UnsignedInteger[] dns_plaintext = AES_GCM.aes_gcm_decrypt(tk_capp, iv_capp, appl_ct);

    return new UnsignedInteger[][]{dns_plaintext, tk_shs, iv_shs, tk_capp, iv_capp, H_3, SF_calculated};
  }




  public static UnsignedInteger[][] quic_get1RTT_HS_new(UnsignedInteger[] HS, UnsignedInteger[] H2, UnsignedInteger TR3_len, UnsignedInteger[] CertVerifyTail_ServerFinished_ct, UnsignedInteger CertVerify_tail_len, UnsignedInteger[] SHA_H_Checkpoint, UnsignedInteger[] http3_request_ct, UnsignedInteger CertVerify_tail_head_len, UnsignedInteger http3_request_head_len) {

    // INPUTS ARE CORRECT 






    // KEYS ARE CORRECT 

    UnsignedInteger[] SHTS = HKDF.quic_hkdf_expand_derive_secret(HS, "s hs traffic", H2);

    // traffic key and iv for "server handshake" messages 
    UnsignedInteger[] tk_shs = HKDF.quic_hkdf_expand_derive_tk(SHTS, 16);

    UnsignedInteger[] iv_shs = HKDF.quic_hkdf_expand_derive_iv(SHTS, 12);

    // XOR original IV with the packet number 
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x02)), 8);

    UnsignedInteger TR7_len = TR3_len.subtract(UnsignedInteger.instantiateFrom(8, 36)).copy(16);

    // si deve decifrare tutto il CRYPTO con il corretto IV xorato con il packet number, calcolo Offset in python 

    // Len della head, gcm_block_number e offset passati in input 

    // To decrypt the tail, we need to calculate the GCM counter block number 
    UnsignedInteger gcm_block_number = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);

    // Additionally, the tail might not start perfectly at the start of a block 
    // That is, the length of head may not be a multiple of 16 
    UnsignedInteger offset = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    // This function decrypts the tail with the specific GCM block number and offset within the block (VERY CONVENIENT) 
    UnsignedInteger[] CertVerifyTail_ServerFinished = AES_GCM.aes_gcm_decrypt_128bytes_middle(tk_shs, iv_shs, CertVerifyTail_ServerFinished_ct, gcm_block_number.copy(8), offset.copy(8));


    // This function calculates the hash of TR3 and TR7 where TR7 is TR3 without the last 36 characters 
    // starting with the SHA_H_Checkpoint provided as a checkpoint state of SHA that is common to both transcripts. 
    // The inputs are: 
    // - the checkpoint state 
    // - the length of TR3 and TR7 (the latter must be a prefix of the former) 
    // - the tail of TR3 (the part after the checkpoint) 
    // - the length of the tail up to TR3 
    // - the length of the tail up to TR7 


    UnsignedInteger[][] H7_H3 = SHA2.double_sha_from_checkpoint(SHA_H_Checkpoint, TR3_len.copy(16), TR7_len.copy(16), CertVerifyTail_ServerFinished, CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36)).copy(8), CertVerify_tail_len.copy(8));

    UnsignedInteger[] H_7 = H7_H3[0];
    UnsignedInteger[] H_3 = H7_H3[1];

    // Derive the SF value from transcript hash H7 up to Certificate Verify 
    UnsignedInteger[] fk_S = HKDF.quic_hkdf_expand_derive_secret(SHTS, "finished", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    UnsignedInteger[] SF_calculated = HKDF.hmac(fk_S, H_7);


    UnsignedInteger[] SF_transcript = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    SmartMemory<UnsignedInteger> CertVerifyTail_ServerFinished_RAM = new SmartMemory(CertVerifyTail_ServerFinished, UnsignedInteger.__getClassRef(), new Object[]{"8"});
    for (int i = 0; i < 32; i++) {
      SF_transcript[i].assign(CertVerifyTail_ServerFinished_RAM.read(UnsignedInteger.instantiateFrom(8, i).add(CertVerify_tail_len).add(UnsignedInteger.instantiateFrom(8, 4))), 8);
    }


    // Verify that the two SF values are identical 
    Util.combine_8_into_256(SF_calculated).forceEqual(Util.combine_8_into_256(SF_transcript));

    // OK 
    UnsignedInteger[] dHS = HKDF.quic_hkdf_expand_derive_secret(HS, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] MS = HKDF.hkdf_extract(dHS, Util.new_zero_array(32));

    // OK 
    UnsignedInteger[] CATS = HKDF.quic_hkdf_expand_derive_secret(MS, "c ap traffic", H_3);

    // client application traffic key, iv 
    UnsignedInteger[] tk_capp = HKDF.quic_hkdf_expand_derive_tk(CATS, 16);
    UnsignedInteger[] iv_capp = HKDF.quic_hkdf_expand_derive_iv(CATS, 12);
    iv_capp[iv_capp.length - 1].assign(iv_capp[iv_capp.length - 1].xorBitwise(new BigInteger("" + 0x05)), 8);

    UnsignedInteger http3_request_gcm_block_number = UnsignedInteger.instantiateFrom(8, http3_request_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);
    UnsignedInteger http3_request_offset = UnsignedInteger.instantiateFrom(8, http3_request_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    UnsignedInteger[] http3_request = AES_GCM.aes_gcm_decrypt_128bytes_middle(tk_capp, iv_capp, http3_request_ct, http3_request_gcm_block_number.copy(8), http3_request_offset.copy(8));

    return new UnsignedInteger[][]{http3_request, tk_shs, iv_shs, tk_capp, iv_capp, H_3, SF_calculated};
  }




  public static UnsignedInteger[][] quic_get1RTT_HS_full(UnsignedInteger[] HS, UnsignedInteger[] H2, UnsignedInteger TR3_len, UnsignedInteger[] CertVerifyTail_ServerFinished_ct, UnsignedInteger CertVerify_tail_len, UnsignedInteger[] SHA_H_Checkpoint, UnsignedInteger[] http3_request_ct, UnsignedInteger CertVerify_tail_head_len, UnsignedInteger http3_request_head_len) {

    // INPUTS ARE CORRECT 





    for (int i = 0; i < http3_request_ct.length; i++) {
      CircuitGenerator.__getActiveCircuitGenerator().__addDebugInstruction(http3_request_ct[i], "appl_ct");
    }

    // KEYS ARE CORRECT 

    UnsignedInteger[] SHTS = HKDF.quic_hkdf_expand_derive_secret(HS, "s hs traffic", H2);

    // traffic key and iv for "server handshake" messages 
    UnsignedInteger[] tk_shs = HKDF.quic_hkdf_expand_derive_tk(SHTS, 16);

    UnsignedInteger[] iv_shs = HKDF.quic_hkdf_expand_derive_iv(SHTS, 12);

    // XOR original IV with the packet number 
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x02)), 8);

    UnsignedInteger TR7_len = TR3_len.subtract(UnsignedInteger.instantiateFrom(8, 36)).copy(16);

    // si deve decifrare tutto il CRYPTO con il corretto IV xorato con il packet number, calcolo Offset in python 

    // Len della head, gcm_block_number e offset passati in input 

    // To decrypt the tail, we need to calculate the GCM counter block number 
    UnsignedInteger gcm_block_number = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);

    // Additionally, the tail might not start perfectly at the start of a block 
    // That is, the length of head may not be a multiple of 16 
    UnsignedInteger offset = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    // This function decrypts the tail with the specific GCM block number and offset within the block (VERY CONVENIENT) 
    UnsignedInteger[] CertVerifyTail_ServerFinished = AES_GCM.aes_gcm_decrypt_128bytes_middle(tk_shs, iv_shs, CertVerifyTail_ServerFinished_ct, gcm_block_number.copy(8), offset.copy(8));


    // This function calculates the hash of TR3 and TR7 where TR7 is TR3 without the last 36 characters 
    // starting with the SHA_H_Checkpoint provided as a checkpoint state of SHA that is common to both transcripts. 
    // The inputs are: 
    // - the checkpoint state 
    // - the length of TR3 and TR7 (the latter must be a prefix of the former) 
    // - the tail of TR3 (the part after the checkpoint) 
    // - the length of the tail up to TR3 
    // - the length of the tail up to TR7 


    UnsignedInteger[][] H7_H3 = SHA2.double_sha_from_checkpoint(SHA_H_Checkpoint, TR3_len.copy(16), TR7_len.copy(16), CertVerifyTail_ServerFinished, CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36)).copy(8), CertVerify_tail_len.copy(8));

    UnsignedInteger[] H_7 = H7_H3[0];
    UnsignedInteger[] H_3 = H7_H3[1];

    // Derive the SF value from transcript hash H7 up to Certificate Verify 
    UnsignedInteger[] fk_S = HKDF.quic_hkdf_expand_derive_secret(SHTS, "finished", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    UnsignedInteger[] SF_calculated = HKDF.hmac(fk_S, H_7);


    UnsignedInteger[] SF_transcript = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    SmartMemory<UnsignedInteger> CertVerifyTail_ServerFinished_RAM = new SmartMemory(CertVerifyTail_ServerFinished, UnsignedInteger.__getClassRef(), new Object[]{"8"});
    for (int i = 0; i < 32; i++) {
      SF_transcript[i].assign(CertVerifyTail_ServerFinished_RAM.read(UnsignedInteger.instantiateFrom(8, i).add(CertVerify_tail_len).add(UnsignedInteger.instantiateFrom(8, 4))), 8);
    }


    // Verify that the two SF values are identical 
    Util.combine_8_into_256(SF_calculated).forceEqual(Util.combine_8_into_256(SF_transcript));

    // OK 
    UnsignedInteger[] dHS = HKDF.quic_hkdf_expand_derive_secret(HS, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] MS = HKDF.hkdf_extract(dHS, Util.new_zero_array(32));

    // OK 
    UnsignedInteger[] CATS = HKDF.quic_hkdf_expand_derive_secret(MS, "c ap traffic", H_3);

    // client application traffic key, iv 
    UnsignedInteger[] tk_capp = HKDF.quic_hkdf_expand_derive_tk(CATS, 16);
    UnsignedInteger[] iv_capp = HKDF.quic_hkdf_expand_derive_iv(CATS, 12);
    iv_capp[iv_capp.length - 1].assign(iv_capp[iv_capp.length - 1].xorBitwise(new BigInteger("" + 0x05)), 8);

    UnsignedInteger http3_request_gcm_block_number = UnsignedInteger.instantiateFrom(8, http3_request_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);

    UnsignedInteger[] http3_request = AES_GCM.aes_gcm_decrypt(tk_capp, iv_capp, http3_request_ct);
    for (int i = 0; i < http3_request.length; i++) {
      if (i + 4 >= http3_request.length) {
        http3_request[i].assign(http3_request[http3_request.length - 1], 8);
      } else {
        http3_request[i].assign(http3_request[i + 4], 8);
      }
    }

    return new UnsignedInteger[][]{http3_request, tk_shs, iv_shs, tk_capp, iv_capp, H_3, SF_calculated};
  }







  public static UnsignedInteger[][] quic_get1RTT_HS_new_POL(UnsignedInteger[] HS, UnsignedInteger[] H2, UnsignedInteger TR3_len, UnsignedInteger[] CertVerifyTail_ServerFinished_ct, UnsignedInteger CertVerify_tail_len, UnsignedInteger[] SHA_H_Checkpoint, UnsignedInteger[] http3_request_ct, UnsignedInteger CertVerify_tail_head_len, UnsignedInteger http3_request_head_len, int max_policy_len) {

    // INPUTS ARE CORRECT 






    // KEYS ARE CORRECT 

    UnsignedInteger[] SHTS = HKDF.quic_hkdf_expand_derive_secret(HS, "s hs traffic", H2);

    // traffic key and iv for "server handshake" messages 
    UnsignedInteger[] tk_shs = HKDF.quic_hkdf_expand_derive_tk(SHTS, 16);

    UnsignedInteger[] iv_shs = HKDF.quic_hkdf_expand_derive_iv(SHTS, 12);

    // XOR original IV with the packet number 
    iv_shs[iv_shs.length - 1].assign(iv_shs[iv_shs.length - 1].xorBitwise(new BigInteger("" + 0x02)), 8);

    UnsignedInteger TR7_len = TR3_len.subtract(UnsignedInteger.instantiateFrom(8, 36)).copy(16);

    // si deve decifrare tutto il CRYPTO con il corretto IV xorato con il packet number, calcolo Offset in python 

    // Len della head, gcm_block_number e offset passati in input 

    // To decrypt the tail, we need to calculate the GCM counter block number 
    UnsignedInteger gcm_block_number = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);

    // Additionally, the tail might not start perfectly at the start of a block 
    // That is, the length of head may not be a multiple of 16 
    UnsignedInteger offset = UnsignedInteger.instantiateFrom(8, CertVerify_tail_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    // This function decrypts the tail with the specific GCM block number and offset within the block (VERY CONVENIENT) 
    UnsignedInteger[] CertVerifyTail_ServerFinished = AES_GCM.aes_gcm_decrypt_128bytes_middle(tk_shs, iv_shs, CertVerifyTail_ServerFinished_ct, gcm_block_number.copy(8), offset.copy(8));


    // This function calculates the hash of TR3 and TR7 where TR7 is TR3 without the last 36 characters 
    // starting with the SHA_H_Checkpoint provided as a checkpoint state of SHA that is common to both transcripts. 
    // The inputs are: 
    // - the checkpoint state 
    // - the length of TR3 and TR7 (the latter must be a prefix of the former) 
    // - the tail of TR3 (the part after the checkpoint) 
    // - the length of the tail up to TR3 
    // - the length of the tail up to TR7 


    UnsignedInteger[][] H7_H3 = SHA2.double_sha_from_checkpoint(SHA_H_Checkpoint, TR3_len.copy(16), TR7_len.copy(16), CertVerifyTail_ServerFinished, CertVerify_tail_len.add(UnsignedInteger.instantiateFrom(8, 36)).copy(8), CertVerify_tail_len.copy(8));

    UnsignedInteger[] H_7 = H7_H3[0];
    UnsignedInteger[] H_3 = H7_H3[1];

    // Derive the SF value from transcript hash H7 up to Certificate Verify 
    UnsignedInteger[] fk_S = HKDF.quic_hkdf_expand_derive_secret(SHTS, "finished", (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{0}, 8));
    UnsignedInteger[] SF_calculated = HKDF.hmac(fk_S, H_7);


    UnsignedInteger[] SF_transcript = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{32}, 8);
    SmartMemory<UnsignedInteger> CertVerifyTail_ServerFinished_RAM = new SmartMemory(CertVerifyTail_ServerFinished, UnsignedInteger.__getClassRef(), new Object[]{"8"});
    for (int i = 0; i < 32; i++) {
      SF_transcript[i].assign(CertVerifyTail_ServerFinished_RAM.read(UnsignedInteger.instantiateFrom(8, i).add(CertVerify_tail_len).add(UnsignedInteger.instantiateFrom(8, 4))), 8);
    }


    // Verify that the two SF values are identical 
    Util.combine_8_into_256(SF_calculated).forceEqual(Util.combine_8_into_256(SF_transcript));

    // OK 
    UnsignedInteger[] dHS = HKDF.quic_hkdf_expand_derive_secret(HS, "derived", SHA2.hash_of_empty());

    UnsignedInteger[] MS = HKDF.hkdf_extract(dHS, Util.new_zero_array(32));

    // OK 
    UnsignedInteger[] CATS = HKDF.quic_hkdf_expand_derive_secret(MS, "c ap traffic", H_3);

    // client application traffic key, iv 
    UnsignedInteger[] tk_capp = HKDF.quic_hkdf_expand_derive_tk(CATS, 16);
    UnsignedInteger[] iv_capp = HKDF.quic_hkdf_expand_derive_iv(CATS, 12);
    iv_capp[iv_capp.length - 1].assign(iv_capp[iv_capp.length - 1].xorBitwise(new BigInteger("" + 0x05)), 8);

    UnsignedInteger http3_request_gcm_block_number = UnsignedInteger.instantiateFrom(8, http3_request_head_len.div(UnsignedInteger.instantiateFrom(16, 16))).copy(8);
    UnsignedInteger http3_request_offset = UnsignedInteger.instantiateFrom(8, http3_request_head_len.mod(UnsignedInteger.instantiateFrom(16, 16))).copy(8);


    UnsignedInteger[] http3_request = AES_GCM.aes_gcm_decrypt_POLbytes_middle(tk_capp, iv_capp, http3_request_ct, http3_request_gcm_block_number.copy(8), http3_request_offset.copy(8), max_policy_len);

    return new UnsignedInteger[][]{http3_request, tk_shs, iv_shs, tk_capp, iv_capp, H_3, SF_calculated};
  }








}
