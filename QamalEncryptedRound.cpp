//
// Created by Alina Alinovna on 27.02.2021.
//

#include "QamalEncryptedRound.h"

/**
 Add round key
 */

CtxtState QamalEncryptedRound::addRoundKey(const CtxtState &oldState, const CtxtState &key) {
    CtxtState newState(oldState);
    struct timeval start, end;
    gettimeofday(&start, NULL);
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 8; j++)
            newState[i][j] += key[i][j];
    gettimeofday(&end, NULL);
    cout<<"addRoundKey is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
    return newState;
}

/**
 Functions for SBox
 */

int QamalEncryptedRound::getLastMonomIndex(string monomLabel) {
    char last = monomLabel.back();
    return  last - '0';
}

int QamalEncryptedRound::getFirstMonomIndex(string monomLabel) {
    char first = monomLabel.front();
    return  first - '0';
}

CtxtMonomsOfSameDegree QamalEncryptedRound::computeMonomsOfNextDegree(const CtxtMonomsOfSameDegree &lMonoms, const CtxtMonomsOfSameDegree &rMonoms) {
    CtxtMonomsOfSameDegree encryptedMonomsOfNextDegree;
    for (const auto& [lKey, lValue] : lMonoms) {
        //std::cout << lKey << " = " << lValue << "; ";
        int leftLastIndex = getLastMonomIndex(lKey);
        for (const auto& [rKey, rValue] : rMonoms) {
            // cout<<"lKey ="<<lKey<<" "<<leftLastIndex<<endl;
            int rightFirstIndex = getFirstMonomIndex(rKey);
            //  cout<<"rKey ="<<rKey<<" "<<rightFirstIndex<<endl;
            if (leftLastIndex >= rightFirstIndex) continue;
            Ctxt nextMonom(lValue);
            nextMonom *= rValue;
            // cout<<nextMonom<<endl;
            /*encryptedMonomsOfNextDegree[lKey + rKey] = nextMonom;*/
            encryptedMonomsOfNextDegree.insert ( std::pair<string , Ctxt>(lKey + rKey, nextMonom) );
            // cout<<"lKey + rKey="<<lKey + rKey<<endl;
        }
        //cout<<endl;
    }
    // cout << "\n";
    return encryptedMonomsOfNextDegree;
}

CtxtMonoms QamalEncryptedRound::computeMonomsForSBox(const CtxtByte &encryptedByte) {
    vector<CtxtMonomsOfSameDegree> encryptedMonoms(7);
    CtxtMonomsOfSameDegree encryptedMonomsOfDegree1;
    for (int i = 0; i < encryptedByte.size(); i++) {
        encryptedMonomsOfDegree1.insert ( std::pair<string , Ctxt>(to_string(i),encryptedByte[i]) );
        //encryptedMonomsOfDegree1.[to_string(i)] = encryptedByte[i];
       // cout<<to_string(i)<<endl;
    }
    encryptedMonoms[0] = encryptedMonomsOfDegree1;

    for (int i = 2; i < 8; i++) {
        vector<int> degreeSplitting = CommonData::splitting.at(i);
        int lDegree = degreeSplitting[0];
        int rDegree = degreeSplitting[1];
        encryptedMonoms[i - 1] =  computeMonomsOfNextDegree(encryptedMonoms[lDegree - 1], encryptedMonoms[rDegree - 1]);
    }
    return encryptedMonoms;
}

Ctxt QamalEncryptedRound::computeSBoxPoly(const CtxtMonoms &monoms, const vector<string> &SBox) {
    int degree = SBox[0].length();
    Ctxt start =  degree == 0 ? Ctxt(*oneEncrypted) : Ctxt(monoms[degree - 1].at(SBox[0]));
    for(int i = 1; i < SBox.size(); i++) {
        string monomLabel = SBox[i];
       // cout<<monomLabel<<" ";
        degree = monomLabel.length();
        start += monoms[degree - 1].at(monomLabel);
    }
    return  start;
}

CtxtByte QamalEncryptedRound::computeSBox(const CtxtMonoms &monoms) {
    CtxtByte newEncryptedByte;
    for(int i = 0 ; i < CommonData::SBoxes.size(); i++) {
       // cout<<endl<<"Compute SBox"<<i<<endl;
        newEncryptedByte.push_back(computeSBoxPoly(monoms, CommonData::SBoxes[i]));
    }
    return newEncryptedByte;
}

CtxtState QamalEncryptedRound::applySBox(const CtxtState &oldState) {
    cout<<"Start encrypted SBox. "<<endl;
    struct timeval start, end; 
    gettimeofday(&start, NULL);
    CtxtState newState;
    for (int i = 0; i < oldState.size(); i++) {
        cout <<"Process " << i << "th byte of state"<<endl;
        CtxtMonoms monoms = computeMonomsForSBox(oldState[i]);
        CtxtByte newEncryptedByte = computeSBox(monoms);
        newState.push_back(newEncryptedByte);
    }
    gettimeofday(&end, NULL);
    cout<<endl<<"SBox calculation is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
    return newState;
}

/**
 Functions for Mixer1
 */

CtxtByte QamalEncryptedRound::shlEncryptedByteBy2(CtxtByte encryptedByte) {
    CtxtByte shiftedByte;
    shiftedByte.push_back(*zeroEncrypted);
    for(int j = 0; j <= 6 ; j++) {
        shiftedByte.push_back(encryptedByte[j]);
    }
    return  shiftedByte;
}

CtxtByte QamalEncryptedRound::shlEncryptedByteBy4(CtxtByte encryptedByte) {
    return shlEncryptedByteBy2(shlEncryptedByteBy2(encryptedByte));
}

CtxtByte QamalEncryptedRound::shlEncryptedByteBy8(CtxtByte encryptedByte) {
    return shlEncryptedByteBy4(shlEncryptedByteBy2(encryptedByte));
}

CtxtByte QamalEncryptedRound::calcEncryptedSum(vector<CtxtByte> summands, vector<helib::zzX> unpackSlotEncoding) {
    CtxtByte encrypted_result;
    helib::CtPtrs_vectorCt result_wrapper(encrypted_result);
    helib::CtPtrMat_vectorCt summands_wrapper(summands);
    helib::addManyNumbers(
            result_wrapper,
            summands_wrapper,
            8,                    // sizeLimit=0 means use as many bits as needed.
            &unpackSlotEncoding);
    return result_wrapper.v;
}

CtxtState QamalEncryptedRound::applyMixer1(const CtxtState &oldState, vector<helib::zzX> unpackSlotEncoding) {
    cout<<endl<<"Start encrypted Mixer1. "<<endl;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    CtxtState newState;
    for(int i = 0 ; i < 16 ; i = i+4) {
        vector<CtxtByte> summandsA1 = {oldState[i], oldState[i+1], oldState[i+2], oldState[i+3]};
        CtxtByte newEncryptedByteA1 = calcEncryptedSum(summandsA1, unpackSlotEncoding);

        vector<CtxtByte> summandsA2 = {shlEncryptedByteBy2(oldState[i]),
                                       shlEncryptedByteBy2(oldState[i+1]),
                                       shlEncryptedByteBy2(oldState[i+2]),
                                       oldState[i+3]
        };
        CtxtByte newEncryptedByteA2 = calcEncryptedSum(summandsA2, unpackSlotEncoding);

        vector<CtxtByte> summandsA3 = {shlEncryptedByteBy4(oldState[i]),
                                       shlEncryptedByteBy4(oldState[i+1]),
                                       shlEncryptedByteBy2(oldState[i+2]),
                                       oldState[i+2],
                                       shlEncryptedByteBy2(oldState[i+3])
        };
        CtxtByte newEncryptedByteA3 = calcEncryptedSum(summandsA3, unpackSlotEncoding);

        vector<CtxtByte> summandsA4 = {shlEncryptedByteBy8(oldState[i]),
                                       shlEncryptedByteBy4(oldState[i+1]),
                                       shlEncryptedByteBy2(oldState[i+1]),
                                       oldState[i+1],
                                       shlEncryptedByteBy4(oldState[i+2]),
                                       shlEncryptedByteBy2(oldState[i+2]),
                                       shlEncryptedByteBy4(oldState[i+3])
        };
        CtxtByte newEncryptedByteA4 = calcEncryptedSum(summandsA4, unpackSlotEncoding);

        newState.push_back(newEncryptedByteA4);
        newState.push_back(newEncryptedByteA3);
        newState.push_back(newEncryptedByteA2);
        newState.push_back(newEncryptedByteA1);
    }
    gettimeofday(&end, NULL);
    cout<<endl<<"Mixer1 encrypted calculation is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
    return  newState;
}

/**
 Functions for Mixer2
 */

Ctxt QamalEncryptedRound::applyMuPolyToEncryptedStateRowToGetOneEncryptedBit(const vector<CtxtByte> &encryptedRow, const vector<int> &muPoly) {
    Ctxt start(*zeroEncrypted);
    for(int i = 0 ; i < muPoly.size(); i++) {
        int rowElemNum = muPoly[i] / 8;
        int bitNum = muPoly[i] % 8;
        start += encryptedRow[rowElemNum][bitNum];
    }
    return  start;
}

CtxtByte QamalEncryptedRound::applyMuPolySetToEncryptedStateRowToGetNewEncryptedStateByte(const vector<CtxtByte> &encryptedRow, const vector<vector<int>> &muPolySet) {
    //row must have length 4
    //muPolySet must have length 8
    CtxtByte encryptedByte;
    for (int i = 0 ; i < muPolySet.size(); i++) {
        Ctxt newEncryptedBit = applyMuPolyToEncryptedStateRowToGetOneEncryptedBit(encryptedRow, muPolySet[i]);
        //cout << i << " " << static_cast<unsigned>(newBit) << "  " << (newBit << i) << endl;
        encryptedByte.push_back(newEncryptedBit);
    }
    return  encryptedByte;
}

vector<CtxtByte> QamalEncryptedRound::applyMixer2ToGetNewEncryptedStateRow(const vector<CtxtByte> &encryptedRow, const vector<vector<vector<int>>> &muPolySets) {
    // muPolySets must have length 4
    vector<CtxtByte> newEncryptedRow;
    for (int i = 0 ; i < muPolySets.size(); i++) {
        newEncryptedRow.push_back(applyMuPolySetToEncryptedStateRowToGetNewEncryptedStateByte(encryptedRow, muPolySets[i]));
    }
    return newEncryptedRow;
}

CtxtState QamalEncryptedRound::applyMixer2(const CtxtState &state) {
    cout<<"Start encrypted Mixer2. "<<endl;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    CtxtState newState(16);
    vector<vector<vector<int>>> muPolySetsForRow = {CommonData::Mu0PolySet, CommonData::Mu0PolySet, CommonData::Mu0PolySet, CommonData::Mu0PolySet};  // later for each row wi will have different set
    for(int i = 0; i < 4; i++) {
        vector<CtxtByte> newEncryptedRow = applyMixer2ToGetNewEncryptedStateRow({state[i], state[i + 4], state[i + 8], state[i + 12]}, muPolySetsForRow);
        newState[i] = newEncryptedRow[0];
        newState[i + 4] = newEncryptedRow[1];
        newState[i + 8] = newEncryptedRow[2];
        newState[i + 12] = newEncryptedRow[3];
    }
    gettimeofday(&end, NULL);
    cout<<endl<<"Mixer2 encrypted calculation is done in "<<CommonData::eval_time(start, end)<<" milliseconds"<<endl;
    return newState;
}

/**
 Calculate round
 */

CtxtState QamalEncryptedRound::calculateEncryptedQamalRound(const CtxtState &oldState, const CtxtState &key, vector<helib::zzX> unpackSlotEncoding) {
    cout<<"Start encrypted Qamal decryption round."<<endl;
    printStateCapacities(oldState);
    CtxtState stateAfterAddingRoundKey = addRoundKey(oldState, key);
    printStateCapacities(stateAfterAddingRoundKey);
    CtxtState stateAfterSbox = applySBox(stateAfterAddingRoundKey);
    printStateCapacities(stateAfterSbox);
    CtxtState stateAfterMixer1 = applyMixer1(stateAfterSbox, unpackSlotEncoding);
    printStateCapacities(stateAfterMixer1);
    CtxtState stateAfterMixer2 = applyMixer2(stateAfterMixer1);
    printStateCapacities(stateAfterMixer2);
    cout<<"Finished encrypted round."<<endl;
    return stateAfterMixer2;
}

void QamalEncryptedRound::printStateCapacities(const CtxtState &state) {
    cout<<"Capacities:"<<endl;
    for (int i = 0; i < state.size(); i++) {
        for (int j = 0; j <  state[i].size(); j++) {
            cout << "(" << 8*i + j << ", " << state[i][j].capacity() << "), ";
        }
    }
    cout<<endl;
}



//unnecessary stuff
/* long *plaintext = new long[bitSize];
 long *qamalKey = new long[bitSize];
 NTL::VectorRandomBnd(bitSize, plaintext, 2);
 NTL::VectorRandomBnd(bitSize, qamalKey, 2);
 printVec(plaintext, bitSize);
 printVec(qamalKey, bitSize);

 helib::Ctxt scratch(public_key);
 std::vector<helib::Ctxt> encryptedPlaintext(bitSize, scratch);
 std::vector<helib::Ctxt> encryptedQamalKey(bitSize, scratch);

 for (long i = 0; i < bitSize; ++i) {
     std::vector<long> p_vec(ea.size());
     std::vector<long> k_vec(ea.size());
     for (long j = 0; j < p_vec.size(); j++) {
         p_vec[j] = plaintext[i];
     }
     for (long j = 0; j < k_vec.size(); j++) {
         k_vec[j] = qamalKey[i];
     }
     ea.encrypt(encryptedPlaintext[i], public_key, p_vec);
     ea.encrypt(encryptedQamalKey[i], public_key, k_vec);
 }*/


/*std::vector<helib::Ctxt> output(bitSize, helib::Ctxt(secret_key));
helib::CtPtrs_vectorCt output_wrapper(output);


helib::bitwiseXOR(output_wrapper, helib::CtPtrs_vectorCt(encryptedPlaintext),
                  helib::CtPtrs_vectorCt(encryptedQamalKey));

std::vector<long> decrypted_result;
helib::decryptBinaryNums(decrypted_result, output_wrapper, secret_key, ea);

for (std::size_t i = 0; i < decrypted_result.size(); ++i) {
    std::cout << decrypted_result[i] << " ";// Use a scratch ciphertext to populate vectors.
}

std::cout << std::endl;*/