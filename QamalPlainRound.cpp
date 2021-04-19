//
// Created by Alina Alinovna on 27.02.2021.
//

#include "QamalPlainRound.h"

pt_state QamalPlainRound::addRoundKey(const pt_state &state, const pt_state &key) {
    cout<<"Start addRoundKey."<<endl;
    pt_state newState(16);
    for(int i = 0 ; i < 16 ; i++) {
        newState[i] = state[i] ^ key[i];
    }
    CommonData::print_state(newState);
    return newState;
}

u8 QamalPlainRound::applySBoxToByte(const u8 byte) {
    return CommonData::SBoxesTable[byte];
}

pt_state QamalPlainRound::applySBox(const pt_state &state) {
    cout<<"Start SBox."<<endl;
    pt_state newState(16);
    for(int i = 0 ; i < 16 ; i++) {
        newState[i] = QamalPlainRound::applySBoxToByte(state[i]);
    }
    CommonData::print_state(newState);
    return newState;
}

pt_state  QamalPlainRound::applyMixer1(const pt_state &state) {
    //state must have length = 16
    cout<<"Start Mixer1."<<endl;
    pt_state newState(state);
    for(int k = 0; k < 4; k++){
        for(int i = 0 ; i < 16 ; i = i+4) {
            int sum = 0;
            for(int j = i; j < i + 4 ; j++) {
                sum += static_cast<unsigned>(newState[j]);
            }
            for(int j = i+2; j >= i ; j--) {
                newState[j+1] = newState[j];
            }
            newState[i] = sum % 256;
        }
    }
    CommonData::print_state(newState);
    return newState;
}

pt_state QamalPlainRound::applyMixer1Version2(const pt_state &state) {
    //state must have length = 16
    cout<<"Start Mixer1 V2."<<endl;
    pt_state newState(state);
    for(int i = 0 ; i < 16 ; i = i+4) {
        int a1 = (newState[i] + newState[i+1] + newState[i+2] + newState[i+3]) % 256;
        int a2 = (2*newState[i] + 2*newState[i+1] + 2*newState[i+2] + newState[i+3]) % 256;
        int a3 = (4*newState[i] + 4*newState[i+1] + 3*newState[i+2] + 2*newState[i+3]) % 256;
        int a4 = (8*newState[i] + 7*newState[i+1] + 6*newState[i+2] + 4*newState[i+3]) % 256;
        newState[i] = a4;
        newState[i+1] = a3;
        newState[i+2] = a2;
        newState[i+3] = a1;
    }
    CommonData::print_state(newState);
    return newState;
}

u8 QamalPlainRound::applyMuPolyToStateRowToGetOneBit(const vector<u8> &row, const vector<int> &muPoly) {
    //row must have length 4
    u8 res = 0;
    for(int i = 0 ; i < muPoly.size(); i++) {
        int rowElemNum = muPoly[i] / 8;
        int bitNum = muPoly[i] % 8;

        int extractedBit = (row[rowElemNum] >> bitNum)  & 1;
        // cout<<muPoly[i] << " "<<rowElemNum<< " "<< bitNum << " "<< extractedBit<<endl;
        res = res ^ extractedBit;
    }
    return res;
}

u8 QamalPlainRound::applyMuPolySetToStateRawToGetNewStateByte(const vector<u8> &row, const vector<vector<int>> &muPolySet) {
    //row must have length 4
    //muPolySet must have length 8
    u8 res = 0;
    for (int i = 0 ; i < muPolySet.size(); i++) {
        u8 newBit = QamalPlainRound::applyMuPolyToStateRowToGetOneBit(row, muPolySet[i]);
        //  cout << i << " " << static_cast<unsigned>(newBit) << "  " << (newBit << i) << endl;
        res = res + (newBit << i);
    }
    return  res;
}

vector<u8> QamalPlainRound::applyMixer2ToGetNewStateRow(const vector<u8> &row, const vector<vector<vector<int>>> &muPolySets) {
    // muPolySets must have length 4
    vector<u8> newRow(4);
    for (int i = 0 ; i < muPolySets.size(); i++) {
        newRow[i] = QamalPlainRound::applyMuPolySetToStateRawToGetNewStateByte(row, muPolySets[i]);
    }
    return newRow;
}

pt_state QamalPlainRound::applyMixer2(const pt_state &state) {
    cout<<"Start Mixer2."<<endl;
    pt_state newState(16);
    vector<vector<vector<int>>> muPolySetsForRow = {CommonData::Mu0PolySet, CommonData::Mu0PolySet, CommonData::Mu0PolySet, CommonData::Mu0PolySet};  // later for each row wi will have different set
    for(int i = 0; i < 4; i++) {
        vector<u8> newRow = QamalPlainRound::applyMixer2ToGetNewStateRow({state[i], state[i + 4], state[i + 8], state[i + 12]}, muPolySetsForRow);
        newState[i] = newRow[0];
        newState[i + 4] = newRow[1];
        newState[i + 8] = newRow[2];
        newState[i + 12] = newRow[3];
    }
    CommonData::print_state(newState);
    return newState;
}

pt_state QamalPlainRound::calculateRound(const pt_state &state, const pt_state &key){
    cout<<"Round key:"<<endl;
    CommonData::print_state(key);
    cout<<"Initial state:"<<endl;
    CommonData::print_state(state);
    cout<<"Start Qamal decryption round."<<endl;
    pt_state newStateAfterAddingRoundKey = QamalPlainRound::addRoundKey(state, key);
    pt_state newStateAfterSBox = applySBox(newStateAfterAddingRoundKey);
    pt_state newStateAfterMixer1 = applyMixer1Version2(newStateAfterSBox);
    pt_state newState = applyMixer2(newStateAfterMixer1);
    cout<<"Finished round."<<endl;
    CommonData::print_state(newState);
    return newState;
}