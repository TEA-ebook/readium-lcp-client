// Licensed to the Readium Foundation under one or more contributor license agreements.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
// 3. Neither the name of the organization nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


package org.readium.sdkforcare.lcp;

import java.io.IOException;
import java.io.InputStream;

public class Service {
    /**
     * Native Container Pointer.
     * DO NOT USE FROM JAVA SIDE!
     */
    private final long nativePtr;

    private Service(long nativePtr) {
        this.nativePtr = nativePtr;
    }

    public License openLicense(String licenseContent) {
        return this.nativeOpenLicense(this.nativePtr, licenseContent);
    }

    public void injectLicense(String epubPath, String licenseContent) {
        this.nativeInjectLicense(this.nativePtr, epubPath, licenseContent);
    }

    public void injectLicense(String epubPath, License license) {
        this.nativeInjectLicense(this.nativePtr, epubPath, license.getOriginalContent());
    }
    public void decryptFile(String licenseContent, String fileIn, String fileOut) {
	this.nativeDecryptFile(this.nativePtr, licenseContent, fileIn, fileOut);
    }


    /**
     * Returns the native Container pointer.
     * DO NOT USE FROM JAVA SIDE UNLESS TO PASS TO NATIVE CODE!
     * @return Native Container Pointer
     */
    private long getNativePtr() {
        return this.nativePtr;
    }

    private native License nativeOpenLicense(long nativePtr, String licenseContent);

    private native void nativeInjectLicense(long nativePtr, String epubPath, String licenseContent);
//    private native void nativeInjectLicense(long nativePtr, String epubPath, License license);

    private native void nativeDecryptFile(long servicePtr, String licenseContent, String fileIn, String fileOut);
}
