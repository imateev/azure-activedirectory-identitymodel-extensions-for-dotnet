//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

// This file contains derived types that are usefull across multiple handlers / protocols.


using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class CustomSignatureProvider : SignatureProvider
    {
        public CustomSignatureProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        { }

        public bool DisposeCalled { get; set; } = false;

        public bool SignCalled { get; set; } = false;

        public bool VerifyCalled { get; set; } = false;

        public override byte[] Sign(byte[] input)
        {
            SignCalled = true;
            return Encoding.UTF8.GetBytes("SignedBytes");
        }

        public bool VerifyResult { get; set; } = true;

        public override bool Verify(byte[] input, byte[] signature)
        {
            VerifyCalled = true;
            return VerifyResult;
        }

        protected override void Dispose(bool disposing)
        {
            DisposeCalled = true;
        }
    }

    public class CustomCryptoProviderFactory : CryptoProviderFactory
    {
        public CustomCryptoProviderFactory()
        {
        }

        public CustomCryptoProviderFactory(string[] supportedAlgorithms)
        {
            SupportedAlgorithms.AddRange(supportedAlgorithms);
        }

        public List<string> SupportedAlgorithms { get; private set; } = new List<string>();

        public SignatureProvider SignatureProvider { get; set; }

        public HashAlgorithm HashAlgorithm { get; set; }

        public bool CreateForSigningCalled { get; set; } = false;

        public bool CreateForVerifyingCalled { get; set; } = false;

        public bool IsSupportedAlgorithmCalled { get; set; } = false;

        public bool ReleaseAlgorithmCalled { get; set; } = false;

        public bool ReleaseSignatureProviderCalled { get; set; } = false;

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            CreateForSigningCalled = true;
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(key, algorithm))
                return CustomCryptoProvider.Create(CryptoTypes.SignatureProvider, key, algorithm) as SignatureProvider;

            return SignatureProvider;
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            CreateForVerifyingCalled = true;
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(key, algorithm))
                return CustomCryptoProvider.Create(CryptoTypes.SignatureProvider, key, algorithm) as SignatureProvider;

            return SignatureProvider;
        }

        public override HashAlgorithm CreateHashAlgorithm(string algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
                return CustomCryptoProvider.Create(CryptoTypes.HashAlgorithm, algorithm) as HashAlgorithm;

            return HashAlgorithm;
        }

        public override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithmCalled = true;
            foreach (var alg in SupportedAlgorithms)
                if (alg.Equals(algorithm, StringComparison.OrdinalIgnoreCase))
                    return true;

            return false;
        }

        public override void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            ReleaseAlgorithmCalled = true;
            if (CustomCryptoProvider != null)
                CustomCryptoProvider.Release(hashAlgorithm);
            else
                hashAlgorithm.Dispose();
        }

        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            ReleaseSignatureProviderCalled = true;
            if (CustomCryptoProvider != null)
                CustomCryptoProvider.Release(signatureProvider);
            else
                signatureProvider.Dispose();
        }
    }

    public class CustomCryptoProvider : ICryptoProvider
    {
        public SignatureProvider SignatureProvider { get; set; }

        public HashAlgorithm HashAlgorithm { get; set; }

        public bool IsSupportedResult { get; set; } = false;

        public bool CreateCalled { get; set; } = false;

        public bool IsSupportedAlgorithmCalled { get; set; } = false;

        public bool ReleaseCalled { get; set; } = false;

        public object Create(params object[] args)
        {
            CreateCalled = true;
            if (cryptoType == CryptoTypes.SignatureProvider)
                return SignatureProvider;

            if (cryptoType == CryptoTypes.HashAlgorithm)
                return HashAlgorithm;

            return null;
        }

        public bool IsSupportedAlgorithm(params object[] args)
        {
            IsSupportedAlgorithmCalled = true;
            return IsSupportedResult;
        }

        public void Release(object cryptoObject)
        {
            ReleaseCalled = true;
            if (cryptoObject as ICustomObject != null)
                return;

            var disposableObject = cryptoObject as IDisposable;
            if (disposableObject != null)
                disposableObject.Dispose();
        }
    }

    public class CustomHashAlgorithm : SHA256, ICustomObject
    {
        public bool DisposeCalled { get; set; } = false;

        public override void Initialize()
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            DisposeCalled = true;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            throw new NotImplementedException();
        }

        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }
    }

    public interface ICustomObject { }
}
