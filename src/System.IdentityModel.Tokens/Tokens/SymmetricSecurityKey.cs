//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Security.Cryptography;

    public class SymmetricSecurityKey : SecurityKey
    {
        int _keySize;
        byte[] _key;

        public SymmetricSecurityKey(byte[] key)
            : this(key, true)
        {
        }

        public SymmetricSecurityKey(byte[] key, bool cloneBuffer)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (key.Length == 0)
            {
                throw new ArgumentException("SR.GetString(SR.SymmetricKeyLengthTooShort, symmetricKey.Length))");
            }

            _keySize = _key.Length * 8;

            if (cloneBuffer)
            {
                _key = new byte[key.Length];
                Buffer.BlockCopy(key, 0, _key, 0, key.Length);
            }
            else
            {
                _key = key;
            }
        }

        public override int KeySize
        {
            get { return _keySize; }
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool forSigning)
        {
            return null;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return false;
        }

        public virtual byte[] Key
        {
            get { return _key; }
        }

        //public abstract byte[] GenerateDerivedKey(string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset);
        //public abstract ICryptoTransform GetDecryptionTransform(string algorithm, byte[] iv);
        //public abstract ICryptoTransform GetEncryptionTransform(string algorithm, byte[] iv);
        //public abstract int GetIVSize(string algorithm);
        //public abstract KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm);
        //public abstract SymmetricAlgorithm GetSymmetricAlgorithm(string algorithm);
        //public abstract byte[] GetSymmetricKey();
    }
}
