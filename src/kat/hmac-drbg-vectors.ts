/**
 * HMAC-DRBG Known Answer Test (KAT) Vectors
 *
 * Source: NIST CAVS 14.3, HMAC_DRBG test vectors (official download)
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
 *
 * File: HMAC_DRBG.rsp (SHA-256, PredictionResistance = False)
 * Configuration: HMAC_DRBG(SHA-256,256+128,0,0) — no personalization, no additional input
 *
 * Test structure (per CAVS):
 *   1. Instantiate with EntropyInput, Nonce, PersonalizationString (empty)
 *   2. Reseed with EntropyInputReseed, AdditionalInputReseed (empty)
 *   3. Generate (no AdditionalInput) — discard output
 *   4. Generate (no AdditionalInput) — compare to ReturnedBits (1024 bits = 128 bytes)
 *
 * These are the EXACT hex values from the official NIST CAVS download.
 */

import type { KATVector } from '../types/drbg';

/**
 * HMAC_DRBG(SHA-256) test vectors — NIST CAVS 14.3
 * PR=False, EntropyInputLen=256, NonceLen=128,
 * PersonalizationStringLen=0, AdditionalInputLen=0, ReturnedBitsLen=1024
 */
export const HMAC_DRBG_VECTORS: KATVector[] = [
  {
    id: 'CAVS-SHA256-PR-False-Count0',
    securityStrength: 256,
    entropyInput: '06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d',
    nonce: '0e66f71edc43e42a45ad3c6fc6cdc4df',
    personalization: '',
    entropyInputReseed: '01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552',
    additionalInputReseed: '',
    additionalInput1: '',
    additionalInput2: '',
    returnedBits:
      '76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb' +
      '2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842' +
      'e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a802254' +
      '22918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124',
  },
  {
    id: 'CAVS-SHA256-PR-False-Count1',
    securityStrength: 256,
    entropyInput: 'aadcf337788bb8ac01976640726bc51635d417777fe6939eded9ccc8a378c76a',
    nonce: '9ccc9d80c89ac55a8cfe0f99942f5a4d',
    personalization: '',
    entropyInputReseed: '03a57792547e0c98ea1776e4ba80c007346296a56a270a35fd9ea2845c7e81e2',
    additionalInputReseed: '',
    additionalInput1: '',
    additionalInput2: '',
    returnedBits:
      '17d09f40a43771f4a2f0db327df637dea972bfff30c98ebc8842dc7a9e3d681c' +
      '61902f71bffaf5093607fbfba9674a70d048e562ee88f027f630a78522ec6f706' +
      'bb44ae130e05c8d7eac668bf6980d99b4c0242946452399cb032cc6f9fd962847' +
      '09bd2fa565b9eb9f2004be6c9ea9ff9128c3f93b60dc30c5fc8587a10de68c',
  },
  {
    id: 'CAVS-SHA256-PR-False-Count2',
    securityStrength: 256,
    entropyInput: '62cda441dd802c7652c00b99cac3652a64fc75388dc9adcf763530ac31df9214',
    nonce: '5fdc897a0c1c482204ef07e0805c014b',
    personalization: '',
    entropyInputReseed: 'bd9bbf717467bf4b5db2aa344dd0d90997c8201b2265f4451270128f5ac05a1a',
    additionalInputReseed: '',
    additionalInput1: '',
    additionalInput2: '',
    returnedBits:
      '7e41f9647a5e6750eb8acf13a02f23f3be77611e51992cedb6602c314531aff2' +
      'a6e4c557da0777d4e85faefcb143f1a92e0dbac8de8b885ced62a124f0b10620' +
      'f1409ae87e228994b830eca638ccdceedd3fcd07d024b646704f44d5d9c4c3a7b7' +
      '05f37104b45b9cfc2d933ae43c12f53e3e6f798c51be5f640115d45cf919a4',
  },
  {
    id: 'CAVS-SHA256-PR-False-Count3',
    securityStrength: 256,
    entropyInput: '6bdc6ca8eef0e3533abd02580ebbc8a92f382c5b1c8e3eaa12566ecfb90389a3',
    nonce: '8f8481cc7735827477e0e4acb7f4a0fa',
    personalization: '',
    entropyInputReseed: '72eca6f1560720e6bd1ff0152c12eeff1f959462fd62c72b7dde96abcb7f79fb',
    additionalInputReseed: '',
    additionalInput1: '',
    additionalInput2: '',
    returnedBits:
      'd5a2e2f254b5ae65590d4fd1ff5c758e425be4bacdeede7989669f0a22d34274' +
      'fdfc2bf87135e30abdae2691629c2f6f425bd4e119904d4785ecd9328f1525956' +
      '3e5a71f915ec0c02b66655471067b01016fdf934a47b017e07c21332641400bbe' +
      '5719050dba22c020b9b2d2cdb933dbc70f76fec4b1d83980fd1a13c4565836',
  },
  {
    id: 'CAVS-SHA256-PR-False-Count4',
    securityStrength: 256,
    entropyInput: '096ef37294d369face1add3eb8b425895e921626495705c5a03ee566b34158ec',
    nonce: '6e2e0825534d2989715cc85956e0148d',
    personalization: '',
    entropyInputReseed: '1b4f7125f472c253837fa787d5acf0382a3b89c3f41c211d263052402dcc62c5',
    additionalInputReseed: '',
    additionalInput1: '',
    additionalInput2: '',
    returnedBits:
      '4541f24f759b5f2ac2b57b51125077cc740b3859a719a9bab1196e6c0ca2bd05' +
      '7af9d3892386a1813fc8875d8d364f15e7fd69d1cc6659470415278164df6562' +
      '95ba9cfcee79f6cbe26ee136e6b45ec224ad379c6079b10a2e0cb5f7f785ef0ab' +
      '7a7c3fcd9cb6506054d20e2f3ec610cbba9b045a248af56e4f6d3f0c8d96a23',
  },
];
