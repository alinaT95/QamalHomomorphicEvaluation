/* Copyright (C) 2019 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

// This is a sample program for education purposes only.
// It attempts to demonstrate the use of the API for the
// binary arithmetic operations that can be performed.

#include <string>
#include <iostream>
#include <map>
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include <sys/time.h>
#include "CommonData.h"
#include "QamalPlainRound.h"
#include "QamalEncryptedRound.h"

using namespace std;
using namespace helib;

vector<long> pad(long firstElem, long nslots) {
    vector<long> ns;
    ns.push_back(firstElem);
    for (int i = 1; i < nslots; i++)
        ns.push_back(0);
    return ns;
}

vector<vector<long>> encode_byte(u8 inp, long nslots) {
    vector<vector<long> > new_vec;
    for (int j = 0; j < 8; j++)
        new_vec.push_back(pad((inp >> j) & 1, nslots));
    return new_vec;
}

u8 decode_byte(const vector<vector<long>> &inp) {
    u8 elem = 0;
    for (int i = 0; i < 8; i++) {
        elem |= inp[i][0] << i;
    }
    return elem;
}

vector<vector<vector<long>>> encode_state(pt_state inp, long nslots) {
    vector<vector<vector<long>>> vs;
    for (int i = 0; i < 16; i++) {
        vs.push_back(encode_byte(inp[i], nslots));
    }
    return vs;
}

void decode_state(u8 ret[16], const vector<vector<vector<long>>> &inp) {
    for (int i = 0; i < 16; i++) {
        ret[i] = decode_byte(inp[i]);
    }
}

CtxtState encrypt_state
        (
                const EncryptedArray &ea,
                const PubKey &pk,
                pt_state st
        ) {
    vector<vector<vector<long>>> pt(encode_state(st, ea.size()));
    CtxtState c_st;
    for (int i = 0; i < 16; i++) {
        vector<Ctxt> vs;
        for (int j = 0; j < 8; j++) {
            Ctxt new_ctx(pk);
            ea.encrypt(new_ctx, pk, pt[i][j]);
            vs.push_back(new_ctx);
        }
        c_st.push_back(vs);
    }
    return c_st;
}

void decrypt_state(u8 result[16], const CtxtState &c_pt, const EncryptedArray &ea, const SecKey &secretKey) {
    for (int i = 0; i < 16; i++) {
        result[i] = 0;
        for (int j = 0; j < 8; j++) {
            vector<long> v;
            ea.decrypt(c_pt[i][j], secretKey, v);
            result[i] |= (v[0] << j);
        }
        printf("%02x", result[i]);
    }
    printf("\n");
}

CtxtByte encrypt_byte(const EncryptedArray &ea, const PubKey &pk, u8 inp) {
    vector<vector<long>> inp_vec(encode_byte(inp, ea.size()));
    vector<Ctxt> ct_byte;
    for (int i = 0; i < 8; i++) {
        Ctxt new_ctx(pk);
        ea.encrypt(new_ctx, pk, inp_vec[i]);
        ct_byte.push_back(new_ctx);
    }
    return ct_byte;
}

u8 decrypt_byte(const EncryptedArray &ea, const SecKey &sk, CtxtByte inp) {
    vector<vector<long>> derp_vec(8);
    for (int i = 0; i < 8; i++) {
        ea.decrypt(inp[i], sk, derp_vec[i]);
    }
    return decode_byte(derp_vec);
}


int main(int argc, char *argv[]) {
    /*  Example of binary arithmetic using the BGV scheme  */

    // First set up parameters.
    //
    // NOTE: The parameters used in this example code are for demonstration only.
    // They were chosen to provide the best performance of execution while
    // providing the context to demonstrate how to use the "Binary Arithmetic
    // APIs". The parameters do not provide the security level that might be
    // required by real use/application scenarios.

    // Plaintext prime modulus.
    long p = 2;
    // Cyclotomic polynomial - defines phi(m).
  //  long m = 4095;
    // Hensel lifting (default = 1).
    long r = 1;
    // Number of bits of the modulus chain.
    long bits = 800;
    // Number of columns of Key-Switching matrix (typically 2 or 3).
    long c = 2;
    // Factorisation of m required for bootstrapping.
    //std::vector<long> mvec = {m};//{7, 5, 9, 13};
   /* // Generating set of Zm* group.
    std::vector<long> gens = {2341, 3277, 911};
    // Orders of the previous generators.
    std::vector<long> ords = {6, 4, 6};*/

    long m = helib::FindM(128, bits, c, p, r, 1000, 0);
   // std::vector<long> mvec = {m};
    cout<< "m="<<m<<endl;
    std::cout << "\n*********************************************************";
    std::cout << "\n*            Basic Binary Arithmetic Example            *";
    std::cout << "\n*            ===============================            *";
    std::cout << "\n*                                                       *";
    std::cout << "\n* This is a sample program for education purposes only. *";
    std::cout << "\n* It attempts to demonstrate the use of the API for the *";
    std::cout << "\n* binary arithmetic operations that can be performed.   *";
    std::cout << "\n*                                                       *";
    std::cout << "\n*********************************************************";
    std::cout << std::endl;

    std::cout << "Initialising context object..." << std::endl;
    // Initialize the context.
    // This object will hold information about the algebra created from the
    // previously set parameters.
    //helib::Context context(m, p, r, gens, ords);
    helib::Context context(m, p, r);



    // Modify the context, adding primes to the modulus chain.
    // This defines the ciphertext space.
    std::cout << "Building modulus chain..." << std::endl;
    //buildModChain(context, bits, c, /willBeBootstrappable=true);*/
    buildModChain(context, bits, c);

    // Make bootstrappable.
    // Modify the context, providing bootstrapping capabilities.
    // Boostrapping has the affect of 'refreshing' a ciphertext back to a higher
    // level so more operations can be performed.
  //  context.enableBootStrapping(
        //    helib::convert<NTL::Vec<long>, std::vector<long>>(mvec));

    // Print the context.
    context.zMStar.printout();
    std::cout << std::endl;


    // Print the security level.
    std::cout << "Security: " << context.securityLevel() << std::endl;

    // Secret key management.
    std::cout << "Creating secret key..." << std::endl;
    // Create a secret key associated with the context.
    helib::SecKey secret_key(context);
    // Generate the secret key.
    secret_key.GenSecKey();

    // Generate bootstrapping data.
   // secret_key.genRecryptData();

    // Public key management.
    // Set the secret key (upcast: SecKey is a subclass of PubKey).
    const helib::PubKey &public_key = secret_key;

    // Get the EncryptedArray of the context.
    const helib::EncryptedArray &ea = *(context.ea);

    // Build the unpack slot encoding.
    std::vector<helib::zzX> unpackSlotEncoding;
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);

    // Get the number of slot (phi(m)).
    long nslots = ea.size();
    std::cout << "Number of slots: " << nslots << std::endl;

    cout<<"numPrimes = "<<context.numPrimes()<<endl;

    std::cout << "Number of slots: " << nslots << std::endl;

     vector<long> zeroConst = pad(0, nslots);
     Ctxt zeroEncrypted(public_key);
     ea.encrypt(zeroEncrypted, public_key, zeroConst);

     vector<long> oneConst = pad(1, nslots);
     Ctxt oneEncrypted(public_key);
     ea.encrypt(oneEncrypted, public_key, oneConst);

   /* cout<<"capacity="<<oneEncrypted.bitCapacity()<<endl;

     Ctxt pp(oneEncrypted);
     cout<<"initial capacity pp ="<<pp.bitCapacity()<<endl;
     for(int i = 0; i < 46; i++) {
         pp.multiplyBy(oneEncrypted);
         cout<<i<<")capacity pp ="<<pp.bitCapacity()<<endl;
         vector<long> v;
         ea.decrypt(pp, secret_key, v);
         cout<<v[0]<<endl;
     }*/




    pt_roundkey key({
                             0x2b, 0x7e, 0x00, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
                     });
     pt_state data({
                           0x81, 0x89, 0x76, 0x78, 0x89, 0x78, 0x45, 0xfb,
                           0xa2, 0xef, 0xb5, 0xf9, 0xaa, 0xbb, 0x13, 0xf2
                   });

     cout<<"Plain data: "<<endl;
     CommonData::print_state(data);

     cout<<"Round key: "<<endl;
     CommonData::print_state(key);

     int numberOfRounds = 3;

     QamalPlainRound *qamalPlainRound = new QamalPlainRound();


     pt_state stateAfterQamalRound(data);
     struct timeval totalStart, totalEnd;
     gettimeofday(&totalStart, NULL);
     for(int i = 0 ; i < numberOfRounds ; i++) {
         cout<<endl<<"======================================"<<endl;
         cout<<"Started plain Qamal round #"<<i<<endl;
         cout<<"======================================"<<endl;
         struct timeval start, end;
         gettimeofday(&start, NULL);
         stateAfterQamalRound = qamalPlainRound->calculateRound(stateAfterQamalRound, key);
         gettimeofday(&end, NULL);
         cout<<endl<<"======================================"<<endl;
         cout<<" Qamal plain calculation of 1 round is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
         cout<<"======================================"<<endl;
     }

     gettimeofday(&totalEnd, NULL);//second time cut
     cout<<endl<<"======================================"<<endl;
     cout<<" Qamal plain calculation of "<<numberOfRounds<<" rounds is done in "<<CommonData::eval_time(totalStart, totalEnd)<<" milliseconds"<<endl;
     cout<<"======================================"<<endl;
     cout<<endl<<"Calculated one Qamal round: "<<endl;
     CommonData::print_state(stateAfterQamalRound);
     cout<<"======================================"<<endl;

     CtxtState encryptedState(encrypt_state(ea, public_key, data));
     CtxtState encryptedKey(encrypt_state(ea, public_key, key));
     CtxtState newEncryptedState(encryptedState);
     QamalEncryptedRound *qamalEncryptedRound = new QamalEncryptedRound(oneEncrypted, zeroEncrypted);

     gettimeofday(&totalStart, NULL);
     for(int i = 0 ; i < numberOfRounds ; i++) {
         cout<<endl<<"======================================"<<endl;
         cout<<"Started encrypted Qamal round #"<<i<<endl;
         cout<<"======================================"<<endl;
         struct timeval start, end;
         gettimeofday(&start, NULL);
         newEncryptedState = CtxtState(qamalEncryptedRound->calculateEncryptedQamalRound(newEncryptedState, encryptedKey, unpackSlotEncoding));
         gettimeofday(&end, NULL);
         cout<<endl<<"======================================"<<endl;
         cout<<" Qamal encrypted calculation of 1 round is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
         cout<<"======================================"<<endl;
     }
     gettimeofday(&totalEnd, NULL);//second time cut
     cout<<endl<<"======================================"<<endl;
     cout<<" Qamal encrypted calculation of "<<numberOfRounds<<" rounds is done in "<<CommonData::eval_time(totalStart, totalEnd)<<" milliseconds"<<endl;
     cout<<"======================================"<<endl;

     u8 *result = new u8[16];
     decrypt_state(result, newEncryptedState, ea, secret_key);
     cout<<endl<<"Decrypted result after encrypted computation of "<<numberOfRounds<<" Qamal rounds : "<<endl;
     CommonData::print_state_u8(result);
     cout<<endl<<"Plain result after computation of "<<numberOfRounds<<" Qamal rounds : "<<endl;
     CommonData::print_state(stateAfterQamalRound);

    return 0;
}


// pt_state newState = applyPlainMixer1(data);
/*  pt_state newNewState = applyPlainMixer1Vesrion2(data);



  print_state(key);
  print_state(newNewState);

  u8 b0 = decrypt_byte(ea, secret_key, c_pt[0]);
  printf("%02x", b0);
  cout<<endl<<"b0 = "<<static_cast<unsigned>(b0)<<endl;

    // pt_state newState = applyPlainMixer1(data);
  /*  pt_state newNewState = applyPlainMixer1Vesrion2(data);



    print_state(key);
    print_state(newNewState);

    u8 b0 = decrypt_byte(ea, secret_key, c_pt[0]);
    printf("%02x", b0);
    cout<<endl<<"b0 = "<<static_cast<unsigned>(b0)<<endl;

    u8 b1 = decrypt_byte(ea, secret_key, c_pt[1]);
    printf("%02x", b1);
    cout<<endl<<"b1 = "<<static_cast<unsigned>(b1)<<endl;



    CtxtByte shifted = shlEncryptedByteBy2(c_pt[0], zeroEncrypted);
    u8 b2 = decrypt_byte(ea, secret_key, shifted);
    printf("%02x", b2);
    cout<<endl<<"b2 = "<<static_cast<unsigned>(b2)<<endl;

    CtxtByte shifted4 = shlEncryptedByteBy4(c_pt[0], zeroEncrypted);
    u8 b4 = decrypt_byte(ea, secret_key, shifted4);
    printf("%02x", b4);
    cout<<endl<<"b4 = "<<static_cast<unsigned>(b4)<<endl;

    CtxtByte shifted8 = shlEncryptedByteBy8(c_pt[0], zeroEncrypted);
    u8 b8 = decrypt_byte(ea, secret_key, shifted8);
    printf("%02x", b8);
    cout<<endl<<"b8 = "<<static_cast<unsigned>(b8)<<endl;

    CtxtState newState = applyMixer1ToState(c_pt, zeroEncrypted, unpackSlotEncoding);

    //add_key(k_pt, c_pt);

   /* */

//CtxtState newState = applySBoxToState(c_pt, oneEncrypted);

/*  u8 *result = new u8[16];
  decrypt_state(result, newState, ea, secret_key);
  print_state_u8(result);*/

// Use a scratch ciphertext to populate vectors.


/*  helib::Ctxt scratch(public_key);

  std::vector<helib::Ctxt> encrypted_result;
  helib::CtPtrs_vectorCt result_wrapper(encrypted_result);

  std::vector<long> decrypted_result;

  std::vector<CtxtByte> summands = {c_pt[0], c_pt[1], c_pt[2], c_pt[3]};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::addManyNumbers(
          result_wrapper,
          summands_wrapper,
          0,                    // sizeLimit=0 means use as many bits as needed.
          &unpackSlotEncoding); // Information needed for bootstrapping.
*/
// Decrypt and print the result.
/* helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);

 std::cout << "a+b+c = " << decrypted_result.back() << std::endl;
 cout<< result_wrapper.v.size()<<endl;*/

/* u8 ress = decrypt_byte(ea, secret_key, result_wrapper.v);
 printf("%02x", ress);
 cout<<endl<<static_cast<unsigned>(ress)<<endl;*/



// long outSize = 2 * bitSize;
/* long a_data = NTL::RandomBits_long(bitSize);
 long b_data = NTL::RandomBits_long(bitSize);
 long c_data = NTL::RandomBits_long(bitSize);

 std::cout << "Pre-encryption data:" << std::endl;
 std::cout << "a = " << a_data << std::endl;
 std::cout << "b = " << b_data << std::endl;
 std::cout << "c = " << c_data << std::endl;*/

// unsigned long long plaintext = NTL::RandomBits_long(bitSize);
// unsigned long long qamalKey = NTL::RandomBits_long(bitSize);
//std::cout << "plaintext = " << plaintext << std::endl;
//std::cout << "qamalKey = " << qamalKey << std::endl;





/*std::vector<helib::Ctxt> encrypted_a(bitSize, scratch);
std::vector<helib::Ctxt> encrypted_b(bitSize, scratch);
std::vector<helib::Ctxt> encrypted_c(bitSize, scratch);
// Encrypt the data in binary representation.
for (long i = 0; i < bitSize; ++i) {
  std::vector<long> a_vec(ea.size());
  std::vector<long> b_vec(ea.size());
  std::vector<long> c_vec(ea.size());
  // Extract the i'th bit of a,b,c.
  for (auto& slot : a_vec)
    slot = (a_data >> i) & 1;
  for (auto& slot : b_vec)
    slot = (b_data >> i) & 1;
  for (auto& slot : c_vec)
    slot = (c_data >> i) & 1;
  ea.encrypt(encrypted_a[i], public_key, a_vec);
  ea.encrypt(encrypted_b[i], public_key, b_vec);
  ea.encrypt(encrypted_c[i], public_key, c_vec);
}*/

// Although in general binary numbers are represented here as
// std::vector<helib::Ctxt> the binaryArith APIs for HElib use the PtrVector
// wrappers instead, e.g. helib::CtPtrs_vectorCt. These are nothing more than
// thin wrapper classes to standardise access to different vector types, such
// as NTL::Vec and std::vector. They do not take ownership of the underlying
// object but merely provide access to it.
//
// helib::CtPtrMat_vectorCt is a wrapper for
// std::vector<std::vector<helib::Ctxt>>, used for representing a list of
// encrypted binary numbers.
/*
  // Perform the multiplication first and put it in encrypted_product.
  std::vector<helib::Ctxt> encrypted_product;
  helib::CtPtrs_vectorCt product_wrapper(encrypted_product);
  helib::multTwoNumbers(
      product_wrapper,
      helib::CtPtrs_vectorCt(encrypted_a),
      helib::CtPtrs_vectorCt(encrypted_b),
      *//*rhsTwosComplement=*//*false, // This means the rhs is unsigned rather
                                   // than 2's complement.
      outSize, // Outsize is the limit on the number of bits in the output.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Now perform the encrypted sum and put it in encrypted_result.
  std::vector<helib::Ctxt> encrypted_result;
  helib::CtPtrs_vectorCt result_wrapper(encrypted_result);
  helib::addTwoNumbers(
      result_wrapper,
      product_wrapper,
      helib::CtPtrs_vectorCt(encrypted_c),
      *//*negative=*//*false, // This means the number are unsigned rather than 2's
                          // complement.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Decrypt and print the result.
  std::vector<long> decrypted_result;
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "a*b+c = " << decrypted_result.back() << std::endl;

  // Now calculate the sum of a, b and c using the addManyNumbers function.
  encrypted_result.clear();
  decrypted_result.clear();
  std::vector<std::vector<helib::Ctxt>> summands = {encrypted_a,
                                                    encrypted_b,
                                                    encrypted_c};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::addManyNumbers(
      result_wrapper,
      summands_wrapper,
      0,                    // sizeLimit=0 means use as many bits as needed.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Decrypt and print the result.
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "a+b+c = " << decrypted_result.back() << std::endl;

  // This section calculates popcnt(a) using the fifteenOrLess4Four
  // function.
  // Note: the output i.e. encrypted_result should be of size 4
  // because 4 bits are required to represent numbers in [0,15].
  encrypted_result.resize(4lu, scratch);
  decrypted_result.clear();
  encrypted_a.pop_back(); // drop the MSB since we only support up to 15 bits.
  helib::fifteenOrLess4Four(result_wrapper,
                            helib::CtPtrs_vectorCt(encrypted_a));

  // Decrypt and print the result.
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "popcnt(a) = " << decrypted_result.back() << std::endl;*/
  /*u8 b1 = decrypt_byte(ea, secret_key, c_pt[1]);
  printf("%02x", b1);
  cout<<endl<<"b1 = "<<static_cast<unsigned>(b1)<<endl;



  CtxtByte shifted = shlEncryptedByteBy2(c_pt[0], zeroEncrypted);
  u8 b2 = decrypt_byte(ea, secret_key, shifted);
  printf("%02x", b2);
  cout<<endl<<"b2 = "<<static_cast<unsigned>(b2)<<endl;

  CtxtByte shifted4 = shlEncryptedByteBy4(c_pt[0], zeroEncrypted);
  u8 b4 = decrypt_byte(ea, secret_key, shifted4);
  printf("%02x", b4);
  cout<<endl<<"b4 = "<<static_cast<unsigned>(b4)<<endl;

  CtxtByte shifted8 = shlEncryptedByteBy8(c_pt[0], zeroEncrypted);
  u8 b8 = decrypt_byte(ea, secret_key, shifted8);
  printf("%02x", b8);
  cout<<endl<<"b8 = "<<static_cast<unsigned>(b8)<<endl;

  CtxtState newState = applyMixer1ToState(c_pt, zeroEncrypted, unpackSlotEncoding);*/

  //add_key(k_pt, c_pt);

 /* */

//CtxtState newState = applySBoxToState(c_pt, oneEncrypted);

/*  u8 *result = new u8[16];
  decrypt_state(result, newState, ea, secret_key);
  print_state_u8(result);*/

// Use a scratch ciphertext to populate vectors.


/*  helib::Ctxt scratch(public_key);

  std::vector<helib::Ctxt> encrypted_result;
  helib::CtPtrs_vectorCt result_wrapper(encrypted_result);

  std::vector<long> decrypted_result;

  std::vector<CtxtByte> summands = {c_pt[0], c_pt[1], c_pt[2], c_pt[3]};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::addManyNumbers(
          result_wrapper,
          summands_wrapper,
          0,                    // sizeLimit=0 means use as many bits as needed.
          &unpackSlotEncoding); // Information needed for bootstrapping.
*/
// Decrypt and print the result.
/* helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);

 std::cout << "a+b+c = " << decrypted_result.back() << std::endl;
 cout<< result_wrapper.v.size()<<endl;*/

/* u8 ress = decrypt_byte(ea, secret_key, result_wrapper.v);
 printf("%02x", ress);
 cout<<endl<<static_cast<unsigned>(ress)<<endl;*/



// long outSize = 2 * bitSize;
/* long a_data = NTL::RandomBits_long(bitSize);
 long b_data = NTL::RandomBits_long(bitSize);
 long c_data = NTL::RandomBits_long(bitSize);

 std::cout << "Pre-encryption data:" << std::endl;
 std::cout << "a = " << a_data << std::endl;
 std::cout << "b = " << b_data << std::endl;
 std::cout << "c = " << c_data << std::endl;*/

// unsigned long long plaintext = NTL::RandomBits_long(bitSize);
// unsigned long long qamalKey = NTL::RandomBits_long(bitSize);
//std::cout << "plaintext = " << plaintext << std::endl;
//std::cout << "qamalKey = " << qamalKey << std::endl;





/*std::vector<helib::Ctxt> encrypted_a(bitSize, scratch);
std::vector<helib::Ctxt> encrypted_b(bitSize, scratch);
std::vector<helib::Ctxt> encrypted_c(bitSize, scratch);
// Encrypt the data in binary representation.
for (long i = 0; i < bitSize; ++i) {
  std::vector<long> a_vec(ea.size());
  std::vector<long> b_vec(ea.size());
  std::vector<long> c_vec(ea.size());
  // Extract the i'th bit of a,b,c.
  for (auto& slot : a_vec)
    slot = (a_data >> i) & 1;
  for (auto& slot : b_vec)
    slot = (b_data >> i) & 1;
  for (auto& slot : c_vec)
    slot = (c_data >> i) & 1;
  ea.encrypt(encrypted_a[i], public_key, a_vec);
  ea.encrypt(encrypted_b[i], public_key, b_vec);
  ea.encrypt(encrypted_c[i], public_key, c_vec);
}*/

// Although in general binary numbers are represented here as
// std::vector<helib::Ctxt> the binaryArith APIs for HElib use the PtrVector
// wrappers instead, e.g. helib::CtPtrs_vectorCt. These are nothing more than
// thin wrapper classes to standardise access to different vector types, such
// as NTL::Vec and std::vector. They do not take ownership of the underlying
// object but merely provide access to it.
//
// helib::CtPtrMat_vectorCt is a wrapper for
// std::vector<std::vector<helib::Ctxt>>, used for representing a list of
// encrypted binary numbers.
/*
  // Perform the multiplication first and put it in encrypted_product.
  std::vector<helib::Ctxt> encrypted_product;
  helib::CtPtrs_vectorCt product_wrapper(encrypted_product);
  helib::multTwoNumbers(
      product_wrapper,
      helib::CtPtrs_vectorCt(encrypted_a),
      helib::CtPtrs_vectorCt(encrypted_b),
      *//*rhsTwosComplement=*//*false, // This means the rhs is unsigned rather
                                   // than 2's complement.
      outSize, // Outsize is the limit on the number of bits in the output.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Now perform the encrypted sum and put it in encrypted_result.
  std::vector<helib::Ctxt> encrypted_result;
  helib::CtPtrs_vectorCt result_wrapper(encrypted_result);
  helib::addTwoNumbers(
      result_wrapper,
      product_wrapper,
      helib::CtPtrs_vectorCt(encrypted_c),
      *//*negative=*//*false, // This means the number are unsigned rather than 2's
                          // complement.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Decrypt and print the result.
  std::vector<long> decrypted_result;
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "a*b+c = " << decrypted_result.back() << std::endl;

  // Now calculate the sum of a, b and c using the addManyNumbers function.
  encrypted_result.clear();
  decrypted_result.clear();
  std::vector<std::vector<helib::Ctxt>> summands = {encrypted_a,
                                                    encrypted_b,
                                                    encrypted_c};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::addManyNumbers(
      result_wrapper,
      summands_wrapper,
      0,                    // sizeLimit=0 means use as many bits as needed.
      &unpackSlotEncoding); // Information needed for bootstrapping.

  // Decrypt and print the result.
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "a+b+c = " << decrypted_result.back() << std::endl;

  // This section calculates popcnt(a) using the fifteenOrLess4Four
  // function.
  // Note: the output i.e. encrypted_result should be of size 4
  // because 4 bits are required to represent numbers in [0,15].
  encrypted_result.resize(4lu, scratch);
  decrypted_result.clear();
  encrypted_a.pop_back(); // drop the MSB since we only support up to 15 bits.
  helib::fifteenOrLess4Four(result_wrapper,
                            helib::CtPtrs_vectorCt(encrypted_a));

  // Decrypt and print the result.
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  std::cout << "popcnt(a) = " << decrypted_result.back() << std::endl;*/
