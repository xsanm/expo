import * as Crypto from 'expo-crypto';
import {CryptoDigestAlgorithm, CryptoEncoding, CryptoKeyFormat, CryptoKeyUsage} from 'expo-crypto';
import React from 'react';
import {ScrollView, StyleSheet, Text} from 'react-native';

import FunctionDemo, {FunctionDescription} from '../components/FunctionDemo';

const GET_RANDOM_BYTES: FunctionDescription = {
  name: 'getRandomBytes',
  parameters: [
    {
      name: 'byteCount',
      type: 'number',
      values: [10, 128, 512, 1024],
    },
  ],
  actions: Crypto.getRandomBytes,
};

const GET_RANDOM_BYTES_ASYNC: FunctionDescription = {
  name: 'getRandomBytesAsync',
  parameters: [
    {
      name: 'byteCount',
      type: 'number',
      values: [10, 128, 512, 1024],
    },
  ],
  actions: Crypto.getRandomBytesAsync,
};

const GET_RANDOM_VALUES: FunctionDescription = {
  name: 'getRandomValues',
  parameters: [
    {
      name: 'array',
      type: 'enum',
      values: [
        {
          name: 'new Uint16Array(10)',
          value: new Uint16Array(10),
        },
        {
          name: 'new Int8Array(100)',
          value: new Int8Array(100),
        },
        {
          name: 'new Uint8ClampedArray(1)',
          value: new Uint8ClampedArray(1),
        },
      ],
    },
  ],
  actions: Crypto.getRandomValues,
};

const RANDOM_UUID: FunctionDescription = {
  name: 'randomUUID',
  actions: Crypto.randomUUID,
};

const DIGEST_STRING: FunctionDescription = {
  name: 'digestString',
  parameters: [
    {
      name: 'algorithm',
      type: 'string',
      values: [
        CryptoDigestAlgorithm.MD2,
        CryptoDigestAlgorithm.MD5,
        CryptoDigestAlgorithm.SHA1,
        CryptoDigestAlgorithm.SHA256,
        CryptoDigestAlgorithm.SHA384,
        CryptoDigestAlgorithm.SHA512,
      ],
    },
    {
      name: 'data',
      type: 'string',
      values: ["I'm a string", "I'm not a number"],
    },
    {
      name: 'options',
      type: 'object',
      properties: [
        {
          name: 'encoding',
          type: 'string',
          values: [CryptoEncoding.BASE64, CryptoEncoding.HEX],
        },
      ],
    },
  ],
  actions: Crypto.digestStringAsync,
};

const DIGEST: FunctionDescription = {
  name: 'digest',
  parameters: [
    {
      name: 'algorithm',
      type: 'string',
      values: [
        CryptoDigestAlgorithm.SHA1,
        CryptoDigestAlgorithm.SHA256,
        CryptoDigestAlgorithm.SHA384,
        CryptoDigestAlgorithm.SHA512,
        CryptoDigestAlgorithm.MD2,
        CryptoDigestAlgorithm.MD5,
        CryptoDigestAlgorithm.MD4,
      ],
    },
    {
      name: 'data',
      type: 'enum',
      values: [
        { name: 'new Uint8Array(10).fill(1)', value: new Uint8Array(10).fill(1) },
        { name: 'new Int8Array(100).fill(2)', value: new Int8Array(100).fill(2) },
      ],
    },
  ],
  actions: Crypto.digest,
  renderAdditionalResult: (result: ArrayBuffer) => {
    return <Text>{new Uint8Array(result).map((byte, idx) => Number(byte)).join(', ')}</Text>;
  },
};

//TODO fix global variable
const encryptKey = new Crypto.CryptoKey({ name: 'AES-GCM', length: 32 }, false, [
  CryptoKeyUsage.ENCRYPT,
]);
const decryptKey = new Crypto.CryptoKey({ name: 'AES-GCM', length: 32 }, false, [
  CryptoKeyUsage.DECRYPT,
]);

const rawKey = new Uint8Array( [205, 29, 179, 40, 131, 245, 0, 13, 86, 6, 218, 110, 131, 23, 54, 64, 7, 90, 54, 43, 234, 189, 72, 102, 23, 226, 115, 102, 77, 32, 225, 151]);
Crypto.importKey(CryptoKeyFormat.RAW, rawKey, encryptKey)
Crypto.importKey(CryptoKeyFormat.RAW, rawKey, decryptKey)

const ENCRYPT_AES_GCM: FunctionDescription = {
  name: 'encryptAes',
  parameters: [
    {
      name: 'CryptoKey',
      type: 'constant',
      value: encryptKey,
    },
    {
      name: 'data',
      type: 'string',
      values: ['some random string to encrypt', 'more complicated string !ABC+** /==🤬'],
    },
    {
      name: 'iv',
      type: 'enum',
      values: [{ name: 'new Uint8Array(12).fill(1)', value: new Uint8Array(12).fill(1) }],
    },
  ],
  actions: (key: CryptoKey, data: string, iv: Uint8Array) => {
    return Crypto.encryptAesGcm(key, data, iv);
  },
};

const DECRYPT_AES_GCM: FunctionDescription = {
  name: 'decryptAes',
  parameters: [
    {
      name: 'CryptoKeyTO',
      type: 'constant',
      value: decryptKey,
    },
    {
      name: 'data',
      type: 'string',
      values: [
        'geK5yh7xdiE8t+6KrCSjeRSkdjknMwVF0mNPyvCL/mrDHPmvN1xmcuBbMwRv',
        'n+Kmyh7geCIotOrJviS0dFqwIj8hfQcLkFB0+a8NMF9Rlx0V0t1LVg1l7jKItFlVLE/AyLuz9A==',
      ],
    },
    {
      name: 'iv',
      type: 'enum',
      values: [{ name: 'new Uint8Array(12).fill(1)', value: new Uint8Array(12).fill(1) }],
    },
  ],
  actions: (key: CryptoKey, data: string, iv: Uint8Array) => {
    return Crypto.decryptAesGcm(key, data, iv);
  },
};

const FUNCTIONS_DESCRIPTIONS = [
  GET_RANDOM_BYTES,
  GET_RANDOM_BYTES_ASYNC,
  DIGEST_STRING,
  GET_RANDOM_VALUES,
  RANDOM_UUID,
  DIGEST,
  ENCRYPT_AES_GCM,
  DECRYPT_AES_GCM,
];

function CryptoScreen() {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      {FUNCTIONS_DESCRIPTIONS.map((props, idx) => (
        <FunctionDemo key={idx} namespace="Crypto" {...props} />
      ))}
    </ScrollView>
  );
}

CryptoScreen.navigationOptions = {
  title: 'Crypto',
};

const styles = StyleSheet.create({
  container: {
    padding: 10,
    justifyContent: 'center',
  },
});

export default CryptoScreen;
