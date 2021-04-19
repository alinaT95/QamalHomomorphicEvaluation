//
// Created by Alina Alinovna on 27.02.2021.
//

#ifndef UTILS_QAMALPLAINROUND_H
#define UTILS_QAMALPLAINROUND_H
#include <string>
#include <iostream>
#include <map>
#include "CommonData.h"

using namespace std;
using namespace helib;

class QamalPlainRound {
    //static QamalPlainRound *instance;

public:
    QamalPlainRound() {}
   /* static QamalPlainRound *getInstance() {
        if (!instance)
            instance = new QamalPlainRound;
        return instance;
    }*/

    pt_state addRoundKey(const pt_state &state, const pt_state &key);

    u8 applySBoxToByte(const u8 byte);

    pt_state applySBox(const pt_state &state);

    pt_state applyMixer1(const pt_state &state);

    pt_state applyMixer1Version2(const pt_state &state);

    u8 applyMuPolyToStateRowToGetOneBit(const vector<u8> &row, const vector<int> &muPoly);

    u8 applyMuPolySetToStateRawToGetNewStateByte(const vector<u8> &row, const vector<vector<int>> &muPolySet);

    vector<u8> applyMixer2ToGetNewStateRow(const vector<u8> &row, const vector<vector<vector<int>>> &muPolySets);

    pt_state applyMixer2(const pt_state &state);

    pt_state calculateRound(const pt_state &state, const pt_state &key);
};

#endif //UTILS_QAMALPLAINROUND_H
