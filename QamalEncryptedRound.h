//
// Created by Alina Alinovna on 27.02.2021.
//

#ifndef UTILS_QAMALENCRYPTEDROUND_H
#define UTILS_QAMALENCRYPTEDROUND_H
#include <string>
#include <iostream>
#include <map>
#include "CommonData.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include <sys/time.h>

class QamalEncryptedRound {


public:
    Ctxt *oneEncrypted;
    Ctxt *zeroEncrypted;

    QamalEncryptedRound(Ctxt &oneEncr, Ctxt &zeroEncr) {
        oneEncrypted = new Ctxt(oneEncr);
        zeroEncrypted = new Ctxt(zeroEncr);
    }

    /**
        Add round key
    */

    CtxtState addRoundKey(const CtxtState &oldState, const CtxtState &key);

    /**
        Functions for SBox
    */

    void printStateCapacities(const CtxtState &state);

    int getLastMonomIndex(string monomLabel);

    int getFirstMonomIndex(string monomLabel);

    CtxtMonomsOfSameDegree computeMonomsOfNextDegree(const CtxtMonomsOfSameDegree &lMonoms, const CtxtMonomsOfSameDegree &rMonoms);

    CtxtMonoms computeMonomsForSBox(const CtxtByte &encryptedByte);

    Ctxt computeSBoxPoly(const CtxtMonoms &monoms, const vector<string> &SBox);

    CtxtByte computeSBox(const CtxtMonoms &monoms);

    CtxtState applySBox(const CtxtState &oldState);

    /**
        Functions for Mixer1
    */

    CtxtByte shlEncryptedByteBy2(CtxtByte encryptedByte);

    CtxtByte shlEncryptedByteBy4(CtxtByte encryptedByte);

    CtxtByte shlEncryptedByteBy8(CtxtByte encryptedByte);

    CtxtByte calcEncryptedSum(vector<CtxtByte> summands, vector<helib::zzX> unpackSlotEncoding);

    CtxtState applyMixer1(const CtxtState &oldState, vector<helib::zzX> unpackSlotEncoding);

    /**
        Functions for Mixer2
    */

    Ctxt applyMuPolyToEncryptedStateRowToGetOneEncryptedBit(const vector<CtxtByte> &encryptedRow, const vector<int> &muPoly);

    CtxtByte applyMuPolySetToEncryptedStateRowToGetNewEncryptedStateByte(const vector<CtxtByte> &encryptedRow, const vector<vector<int>> &muPolySet);

    vector<CtxtByte> applyMixer2ToGetNewEncryptedStateRow(const vector<CtxtByte> &encryptedRow, const vector<vector<vector<int>>> &muPolySets);

    CtxtState applyMixer2(const CtxtState &state);

    /**
        Calculate round
    */

    CtxtState calculateEncryptedQamalRound(const CtxtState &oldState, const CtxtState &key, vector<helib::zzX> unpackSlotEncoding);

};


#endif //UTILS_QAMALENCRYPTEDROUND_H
