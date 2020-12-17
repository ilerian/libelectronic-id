/*
 * Copyright (c) 2020 The Web eID Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include "pcsc-mock/pcsc-mock.hpp"

const PcscMock::ApduScript LATEID_IDEMIA_V1_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE = {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},
    // Select authentication certificate file.
    {{0x00, 0xA4, 0x01, 0x0C, 0x02, 0xA0, 0x02}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x07, 0x4d, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x07, 0x4d, 0x30, 0x82, 0x06, 0x35, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0e,
      0x7d, 0xc2, 0x12, 0x34, 0x09, 0xaf, 0xfc, 0x08, 0x00, 0x03, 0x00, 0x00, 0x31, 0x1b, 0x30,
      0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
      0x5c, 0x31, 0x18, 0x30, 0x16, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64,
      0x01, 0x19, 0x16, 0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x31, 0x13, 0x30,
      0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x03,
      0x45, 0x4d, 0x45, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2,
      0x2c, 0x64, 0x01, 0x19, 0x16, 0x03, 0x53, 0x50, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
      0x55, 0x04, 0x03, 0x13, 0x0d, 0x45, 0x2d, 0x4d, 0x45, 0x20, 0x53, 0x49, 0x20, 0x28, 0x43,
      0x41, 0x31, 0x29, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x39, 0x31, 0x32, 0x31, 0x33,
      0x32, 0x36, 0x32, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x38, 0x32, 0x37, 0x30, 0x35,
      0x33, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x6a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
      0x06, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x13, 0x02, 0x4c, 0x56, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13,
      0x41, 0x4e, 0x44, 0x52, 0x49, 0x53, 0x20, 0x50, 0x41, 0x52, 0x41, 0x55, 0x44, 0x5a, 0x49,
      0xc5, 0x85, 0xc5, 0xa0, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x0c,
      0x50, 0x41, 0x52, 0x41, 0x55, 0x44, 0x5a, 0x49, 0xc5, 0x85, 0xc5, 0xa0, 0x31, 0x0f, 0x30,
      0x0d, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x13, 0x06, 0x41, 0x4e, 0x44, 0x52, 0x49, 0x53, 0x31,
      0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0c, 0x30, 0x31, 0x30, 0x31, 0x38,
      0x31, 0x2d, 0x31, 0x35, 0x30, 0x39, 0x38, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
      0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbc, 0x54, 0xba, 0x3b, 0x93,
      0x1b, 0x03, 0x43, 0x0f, 0xed, 0xb2, 0xf5, 0xbf, 0x4e, 0x2f, 0x4e, 0x26, 0xab, 0x6b, 0xe8,
      0x63, 0xcb, 0x86, 0x8d, 0x06, 0xd3, 0xd5, 0x41, 0x84, 0xb3, 0xc1, 0xa7, 0x7d, 0xc2, 0xfb,
      0x2c, 0xfd, 0x80, 0x88, 0x14, 0xc5, 0xda, 0x6b, 0x3d, 0xfe, 0xd8, 0xe1, 0xf8, 0x9e, 0xab,
      0xfd, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x8f, 0x99, 0x03, 0x17, 0xd1, 0x61, 0x6c, 0xc0, 0x2c, 0x73, 0x08, 0xa0, 0xd5, 0x0e, 0x9a,
      0xda, 0xea, 0x13, 0x5b, 0xf7, 0x69, 0xa5, 0x32, 0x3b, 0xbe, 0xb7, 0x41, 0xcd, 0x7f, 0x9f,
      0xf1, 0xca, 0x3a, 0x04, 0xfe, 0x11, 0xd6, 0xe8, 0x39, 0xf1, 0x54, 0xd5, 0x1e, 0x5b, 0x8f,
      0xf5, 0xbb, 0xfa, 0x89, 0xd4, 0x7f, 0x11, 0xfe, 0xd2, 0x39, 0x93, 0x32, 0x92, 0x1e, 0xf8,
      0xf9, 0x8d, 0xcd, 0xa9, 0x01, 0xa3, 0xe4, 0x21, 0xba, 0x9a, 0x04, 0xaf, 0x9b, 0x18, 0xc1,
      0xa9, 0xa2, 0x45, 0x06, 0xb4, 0x24, 0x98, 0x3a, 0x68, 0x24, 0xc1, 0xb0, 0x55, 0x8f, 0x5e,
      0xd0, 0x30, 0x1d, 0xcb, 0x99, 0xf3, 0xa2, 0x67, 0xc4, 0xef, 0xa5, 0xcb, 0x85, 0x2b, 0x55,
      0x8f, 0x68, 0x6c, 0xa7, 0xad, 0x5c, 0x25, 0x52, 0x09, 0xb0, 0xf7, 0xc6, 0x7d, 0xd9, 0x64,
      0xe9, 0xcd, 0x84, 0x4f, 0x26, 0x40, 0x5b, 0xbc, 0x7b, 0xee, 0x3e, 0xfc, 0x6b, 0xb0, 0x0d,
      0x5c, 0x62, 0x9d, 0x16, 0xd0, 0xc5, 0x22, 0x88, 0x71, 0xf5, 0x62, 0xa3, 0xdc, 0x6d, 0xd1,
      0xb8, 0x48, 0xd3, 0x75, 0xcc, 0x17, 0xfa, 0xad, 0x20, 0x26, 0xa9, 0xb3, 0x8a, 0x11, 0xc1,
      0x56, 0xee, 0x62, 0xb0, 0x9f, 0xf6, 0xe6, 0xf2, 0x18, 0x7a, 0xcf, 0x15, 0xce, 0x01, 0xba,
      0xaf, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x21, 0xb7, 0x14, 0x22, 0x67, 0x1a, 0x74, 0x78, 0x92, 0x56, 0xc8, 0x88, 0xee, 0x8a, 0xe9,
      0x2d, 0xf0, 0xb7, 0x65, 0x7d, 0x9e, 0xb3, 0x89, 0x3b, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
      0x82, 0x03, 0xfd, 0x30, 0x82, 0x03, 0xf9, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
      0x16, 0x04, 0x14, 0x16, 0xbc, 0x34, 0x72, 0xd3, 0xd5, 0xfc, 0x89, 0xf8, 0x4c, 0x19, 0x18,
      0x60, 0xde, 0x53, 0xf6, 0xb9, 0x09, 0x52, 0x6c, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
      0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xd1, 0xbc, 0xdd, 0x59, 0x57, 0x90, 0xf1, 0xbb, 0xab,
      0x9b, 0x29, 0xcb, 0x16, 0x47, 0x60, 0x8c, 0x32, 0xdd, 0x47, 0xbc, 0x30, 0x81, 0xe1, 0x06,
      0x03, 0x55, 0x1d, 0x1f, 0x04, 0x81, 0xd9, 0x30, 0x81, 0xd6, 0x30, 0x81, 0xd3, 0xa0, 0x81,
      0xd0, 0xa0, 0x81, 0xcd, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x64, 0x70, 0x2f, 0x45, 0x2d,
      0x4d, 0x45, 0x25, 0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29,
      0x28, 0x33, 0x29, 0x2e, 0x63, 0x72, 0x6c, 0x86, 0x81, 0x9a, 0x6c, 0x64, 0x61, 0x70, 0x3a,
      0x2f, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x2f, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x6e, 0x3d, 0x45, 0x2d, 0x4d, 0x45,
      0x25, 0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33,
      0x29, 0x2c, 0x6f, 0x75, 0x3d, 0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0x61, 0x63,
      0x69, 0x6a, 0x61, 0x73, 0x25, 0x32, 0x30, 0x70, 0x61, 0x6b, 0x61, 0x6c, 0x70, 0x6f, 0x6a,
      0x75, 0x6d, 0x75, 0x25, 0x32, 0x30, 0x64, 0x61, 0x6c, 0x61, 0x2c, 0x6f, 0x3d, 0x45, 0x2d,
      0x4d, 0x45, 0x2c, 0x63, 0x3d, 0x6c, 0x76, 0x3f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
      0x63, 0x61, 0x74, 0x65, 0x72, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x6c,
      0x69, 0x73, 0x74, 0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
      0x63, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
      0x74, 0x69, 0x6f, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x82,
      0x01, 0x1b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x82, 0x01,
      0x0d, 0x30, 0x82, 0x01, 0x09, 0x30, 0x3a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x30, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x02, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
      0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x61, 0x69, 0x61, 0x2f, 0x45, 0x2d, 0x4d, 0x45, 0x25,
      0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33, 0x29,
      0x2e, 0x63, 0x72, 0x74, 0x30, 0x81, 0x9b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x30, 0x02, 0x86, 0x81, 0x8e, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x65, 0x6d, 0x65,
      0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x6e, 0x3d, 0x45, 0x2d, 0x4d, 0x45, 0x25, 0x32, 0x30, 0x53,
      0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33, 0x29, 0x2c, 0x6f, 0x75,
      0x3d, 0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0x61, 0x63, 0x69, 0x6a, 0x61, 0x73,
      0x25, 0x32, 0x30, 0x70, 0x61, 0x6b, 0x61, 0x6c, 0x70, 0x6f, 0x6a, 0x75, 0x6d, 0x75, 0x25,
      0x32, 0x30, 0x64, 0x61, 0x6c, 0x61, 0x2c, 0x6f, 0x3d, 0x45, 0x2d, 0x4d, 0x45, 0x2c, 0x63,
      0x3d, 0x6c, 0x76, 0x3f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
      0x74, 0x65, 0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63,
      0x6c, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x61, 0x73, 0x73, 0x3d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
      0x6f, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x2d, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x21, 0x68, 0x74, 0x74, 0x70, 0x73,
      0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f,
      0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x2e, 0x65, 0x6d, 0x65, 0x30, 0x0c,
      0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
      0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x3c,
      0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07, 0x04, 0x2f, 0x30, 0x2d,
      0x06, 0x25, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x08, 0x84, 0xb5, 0x85, 0x50,
      0x85, 0xc0, 0x8d, 0x7d, 0x81, 0xf1, 0x91, 0x28, 0xe9, 0xa1, 0x06, 0x84, 0x8f, 0x95, 0x06,
      0x81, 0x14, 0x85, 0x95, 0x81, 0x1e, 0xb8, 0xd7, 0x7b, 0x02, 0x01, 0x64, 0x02, 0x01, 0x15,
      0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x18, 0x30, 0x16, 0x06, 0x0a, 0x2b, 0x06,
      0x01, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x03, 0x02, 0x30, 0x82, 0x01, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x82, 0x01, 0x01,
      0x30, 0x81, 0xfe, 0x30, 0x81, 0xfb, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xfa,
      0x3d, 0x01, 0x01, 0x01, 0x30, 0x81, 0xeb, 0x30, 0x81, 0xbe, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x81, 0xb1, 0x1e, 0x81, 0xae, 0x00, 0x53, 0x00, 0x69,
      0x00, 0x73, 0x00, 0x20, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00,
      0x66, 0x00, 0x69, 0x00, 0x6b, 0x00, 0x61, 0x00, 0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x69,
      0x00, 0x72, 0x00, 0x20, 0x00, 0x69, 0x00, 0x65, 0x00, 0x6b, 0x00, 0x6c, 0x00, 0x61, 0x00,
      0x75, 0x00, 0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x4c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x76,
      0x00, 0x69, 0x00, 0x6a, 0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00, 0x52, 0x00, 0x65, 0x00,
      0x70, 0x00, 0x75, 0x00, 0x62, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x6b, 0x00, 0x61, 0x00, 0x73,
      0x00, 0x20, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x73, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x65, 0x00,
      0x67, 0x90, 0x00}},

    {{0x00, 0xb0, 0x05, 0xa8, 0xb5},
     {0x00, 0x74, 0x00, 0x61, 0x00, 0x20, 0x00, 0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
      0x6f, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x20, 0x00, 0x61, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x69,
      0x00, 0x65, 0x00, 0x63, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x61, 0x00,
      0x20, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x6b, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x6e,
      0x00, 0x74, 0x00, 0x61, 0x30, 0x28, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x01, 0x16, 0x1c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
      0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72,
      0x79, 0x30, 0x29, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0a, 0x04,
      0x1c, 0x30, 0x1a, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14,
      0x02, 0x02, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
      0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03,
      0x82, 0x01, 0x01, 0x00, 0x36, 0xb1, 0xae, 0x66, 0xad, 0x40, 0xe5, 0x2c, 0x86, 0x0b, 0xd6,
      0x76, 0x90, 0x00}},

    {{0x00, 0xb0, 0x06, 0x5d, 0xb5},
     {0xd9, 0xa1, 0x82, 0xdd, 0x52, 0x13, 0xa8, 0x2c, 0x67, 0x7c, 0x81, 0xfb, 0x78, 0x84, 0xe5,
      0x7b, 0x2f, 0xe5, 0x61, 0x4f, 0x2d, 0xf0, 0xa2, 0x7d, 0x61, 0x7b, 0x68, 0x6a, 0x17, 0x46,
      0xef, 0x23, 0xf2, 0x42, 0x64, 0xf0, 0x93, 0x72, 0x3b, 0x8f, 0x4d, 0xa4, 0x80, 0x13, 0xe7,
      0x8f, 0xc9, 0x6e, 0xc0, 0xdd, 0x4a, 0xbf, 0x4d, 0x15, 0x7c, 0x17, 0x16, 0x5b, 0xa9, 0x31,
      0x6e, 0xe4, 0x9a, 0x59, 0xcb, 0x17, 0x55, 0x86, 0x46, 0x12, 0x89, 0xbc, 0xbb, 0x24, 0x84,
      0xf5, 0xb7, 0x4f, 0x8b, 0x89, 0xd3, 0x50, 0xdf, 0x7b, 0x5b, 0x50, 0xd9, 0x8e, 0x7e, 0xf1,
      0x0c, 0x1b, 0xa8, 0xa1, 0xa7, 0x43, 0xc5, 0x47, 0x9e, 0xa4, 0x14, 0x69, 0x47, 0x6f, 0x0b,
      0x29, 0x65, 0x9d, 0xd0, 0x8c, 0x2d, 0xff, 0x82, 0xa2, 0xeb, 0xe6, 0x81, 0x2c, 0x2b, 0x17,
      0x1e, 0xf1, 0x49, 0x25, 0xd1, 0x6a, 0xc9, 0x8a, 0x61, 0xee, 0x24, 0x9e, 0xc3, 0xf7, 0xe8,
      0x8b, 0xc2, 0x85, 0x7c, 0x6a, 0xf9, 0xf3, 0x49, 0x98, 0x2c, 0x2a, 0xa8, 0x8a, 0x29, 0xb9,
      0x1f, 0xde, 0xa3, 0x7c, 0xa3, 0x4c, 0x51, 0x7f, 0xc4, 0x1a, 0x08, 0xd9, 0x59, 0x1e, 0x56,
      0xf0, 0xc8, 0x30, 0xd1, 0x46, 0x22, 0xae, 0xab, 0x79, 0xd1, 0x4a, 0x09, 0xe7, 0x15, 0x2d,
      0xfa, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x07, 0x12, 0x3f},
     {0xcd, 0xc1, 0xcb, 0x44, 0x1d, 0x65, 0x07, 0x64, 0x1e, 0xa3, 0x2a, 0xde, 0x1e,
      0x13, 0x78, 0x08, 0x16, 0x1b, 0x56, 0xaa, 0x96, 0x5c, 0xdc, 0x25, 0xb6, 0x85,
      0x31, 0x4a, 0x2d, 0x20, 0x3f, 0x0b, 0x94, 0x6b, 0x41, 0x7e, 0x8f, 0x3e, 0x66,
      0x15, 0xe3, 0xa2, 0x7a, 0x42, 0xd9, 0x2e, 0x97, 0x30, 0x17, 0xeb, 0x0d, 0x8b,
      0x51, 0x12, 0x22, 0xad, 0x6c, 0x1e, 0xc2, 0x5c, 0xc5, 0xdd, 0x0e, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xcb, 0x3f, 0xff, 0x0a, 0x4d, 0x08, 0x70, 0x06, 0xbf, 0x81, 0x01, 0x02, 0xa0, 0x80,
      0x00},
     {0x70, 0x1e, 0xbf, 0x81, 0x01, 0x1a, 0xa0, 0x18, 0x9a, 0x01, 0x03, 0x9b,
      0x01, 0x03, 0xa1, 0x10, 0x8c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0x43, 0x00,
      0x9c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0x43, 0x00, 0x90, 0x00}},

    // 3. Authenticate.
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},

    // Set env
    {{0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x82}, {0x90, 0x00}},

    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x01, 0x40, 0x31, 0x32, 0x33, 0x34, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
     {0x90, 0x00}},

    // Internal auth
    {{0x00, 0x88, 0x00, 0x00, 0x33, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7,
      0x9f, 0xfd, 0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a, 0x3f, 0xae,
      0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a, 0x00},
     {0x77, 0xe9, 0x22, 0xcf, 0xdc, 0x5e, 0x3e, 0x2d, 0xa2, 0xfe, 0xc2, 0x51, 0x43, 0xf8, 0x44,
      0xed, 0xe6, 0xbb, 0x91, 0x1b, 0xbc, 0xdb, 0x04, 0x12, 0x05, 0xeb, 0x45, 0x49, 0x19, 0x6f,
      0xfe, 0xc5, 0xb9, 0xcf, 0xee, 0x0f, 0x55, 0x75, 0xbb, 0xb1, 0x7d, 0x11, 0xae, 0x5b, 0xc0,
      0x08, 0x3b, 0x13, 0x20, 0x96, 0xc9, 0xf7, 0x83, 0xac, 0x3c, 0xf2, 0x3b, 0x9c, 0x9e, 0xb2,
      0xab, 0x25, 0x10, 0x1e, 0xae, 0x70, 0x7e, 0x81, 0x34, 0x50, 0x89, 0x5b, 0x1d, 0x48, 0xae,
      0x85, 0x94, 0x11, 0x8f, 0xe3, 0x5d, 0xe4, 0x91, 0x3b, 0xcd, 0xc0, 0x30, 0x64, 0xee, 0x79,
      0x2e, 0x57, 0x81, 0xed, 0xb4, 0xe7, 0x5d, 0x69, 0xde, 0x12, 0xde, 0xd5, 0x98, 0xd1, 0xe6,
      0x4b, 0xe6, 0x5f, 0xe5, 0x7f, 0xc9, 0x00, 0x13, 0xc1, 0x67, 0x22, 0x9f, 0xc6, 0xd7, 0x82,
      0xbd, 0xc9, 0x57, 0xb3, 0x70, 0xad, 0x95, 0xf3, 0x30, 0x42, 0xbb, 0xa5, 0xa1, 0x44, 0x84,
      0xcd, 0x74, 0x66, 0xee, 0xa0, 0x98, 0xcc, 0xcf, 0xc0, 0xd2, 0x5c, 0x4c, 0x24, 0x9c, 0xb0,
      0x3d, 0x79, 0xa1, 0x4f, 0xa3, 0x26, 0x51, 0x8b, 0xac, 0xa6, 0x7d, 0xd9, 0x83, 0xd6, 0x08,
      0xef, 0xaf, 0x4d, 0x51, 0xf2, 0x4d, 0xc4, 0x92, 0x41, 0xe1, 0x75, 0xaa, 0xc8, 0xfb, 0xb6,
      0xd1, 0x8f, 0x9f, 0xed, 0x1f, 0x8b, 0x95, 0x5b, 0xd4, 0x03, 0x4a, 0x9c, 0x34, 0x3d, 0x8e,
      0x42, 0x0e, 0x99, 0xf0, 0x96, 0x59, 0x68, 0x0d, 0x97, 0x86, 0xd8, 0x47, 0xe8, 0x2b, 0x99,
      0x37, 0x64, 0xd7, 0xd7, 0x96, 0x74, 0x07, 0xbf, 0x42, 0x4f, 0x2d, 0x65, 0x04, 0x6c, 0x6e,
      0x34, 0xd0, 0x53, 0x00, 0xc3, 0x6c, 0xbf, 0x1c, 0x46, 0x6b, 0x41, 0xe0, 0xdd, 0x63, 0x17,
      0x34, 0xff, 0x31, 0x8e, 0xd3, 0xba, 0xbe, 0x84, 0x02, 0x77, 0xa6, 0x5b, 0xed, 0xac, 0xa0,
      0x43, 0x90, 0x00}}};

const PcscMock::ApduScript LATEID_IDEMIA_V1_SELECT_SIGN_CERTIFICATE_AND_SIGNING = {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},
    // Select signing certificate file.
    {{0x00, 0xA4, 0x01, 0x0C, 0x02, 0xA0, 0x01}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x08, 0xf0, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x08, 0xf0, 0x30, 0x82, 0x07, 0xd8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0e,
      0x7d, 0xc2, 0x12, 0x34, 0x09, 0xaf, 0xfc, 0x08, 0x00, 0x03, 0x00, 0x00, 0x31, 0x1a, 0x30,
      0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
      0x5c, 0x31, 0x18, 0x30, 0x16, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64,
      0x01, 0x19, 0x16, 0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x31, 0x13, 0x30,
      0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x03,
      0x45, 0x4d, 0x45, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2,
      0x2c, 0x64, 0x01, 0x19, 0x16, 0x03, 0x53, 0x50, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
      0x55, 0x04, 0x03, 0x13, 0x0d, 0x45, 0x2d, 0x4d, 0x45, 0x20, 0x53, 0x49, 0x20, 0x28, 0x43,
      0x41, 0x31, 0x29, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x39, 0x31, 0x32, 0x31, 0x33,
      0x32, 0x36, 0x32, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x38, 0x32, 0x37, 0x30, 0x35,
      0x33, 0x35, 0x34, 0x35, 0x5a, 0x30, 0x6a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
      0x06, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x13, 0x02, 0x4c, 0x56, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13,
      0x41, 0x4e, 0x44, 0x52, 0x49, 0x53, 0x20, 0x50, 0x41, 0x52, 0x41, 0x55, 0x44, 0x5a, 0x49,
      0xc5, 0x85, 0xc5, 0xa0, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x0c,
      0x50, 0x41, 0x52, 0x41, 0x55, 0x44, 0x5a, 0x49, 0xc5, 0x85, 0xc5, 0xa0, 0x31, 0x0f, 0x30,
      0x0d, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x13, 0x06, 0x41, 0x4e, 0x44, 0x52, 0x49, 0x53, 0x31,
      0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0c, 0x30, 0x31, 0x30, 0x31, 0x38,
      0x31, 0x2d, 0x31, 0x35, 0x30, 0x39, 0x38, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
      0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc1, 0xf1, 0x7d, 0xaa, 0x7e,
      0x7c, 0xde, 0xab, 0x23, 0x84, 0x12, 0xff, 0x41, 0xc9, 0x47, 0x70, 0xda, 0xe4, 0xdb, 0x39,
      0x10, 0x2a, 0x55, 0x87, 0xd1, 0x23, 0x46, 0x56, 0x19, 0x73, 0x1a, 0x90, 0x88, 0x62, 0xda,
      0x76, 0x09, 0x3d, 0x77, 0xe8, 0xc2, 0x05, 0x71, 0x0c, 0x87, 0xbf, 0x02, 0xdc, 0x37, 0xdf,
      0x38, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0xb9, 0x17, 0xb4, 0x86, 0x16, 0xae, 0x4b, 0x05, 0xa4, 0x69, 0x1d, 0x32, 0xeb, 0xd3, 0x78,
      0xe7, 0xa9, 0x22, 0x71, 0x98, 0x70, 0xe6, 0xd2, 0xc6, 0x58, 0x59, 0xcb, 0x1e, 0x97, 0x41,
      0x5d, 0x06, 0xfc, 0xb5, 0xd8, 0x56, 0x7f, 0x06, 0x07, 0xa8, 0xa2, 0x58, 0x3e, 0xd4, 0x85,
      0x80, 0xb3, 0x7b, 0xff, 0x44, 0xc7, 0x1f, 0x41, 0xf4, 0xd6, 0x87, 0x8e, 0xd1, 0x91, 0x9d,
      0x9d, 0x2f, 0xf4, 0x5f, 0xee, 0x36, 0x3d, 0x5e, 0x33, 0xbe, 0x63, 0xf1, 0x8e, 0xe9, 0xb7,
      0xef, 0xdf, 0x5c, 0xe9, 0xd3, 0xac, 0x8a, 0x96, 0x59, 0x22, 0x14, 0x48, 0x94, 0x42, 0x32,
      0x3b, 0x5e, 0xd0, 0xe9, 0x42, 0x35, 0xd7, 0x1e, 0xf6, 0x0b, 0xd5, 0xe8, 0xbc, 0x10, 0x15,
      0xe0, 0xd3, 0x3b, 0x7e, 0x0f, 0xdc, 0x0a, 0xad, 0x3a, 0x57, 0x8d, 0xbc, 0xa1, 0xaf, 0x2d,
      0x57, 0xb2, 0x73, 0x41, 0xf0, 0x49, 0x18, 0xc4, 0x83, 0x94, 0x04, 0x7c, 0x3f, 0x89, 0x7a,
      0xdb, 0xbc, 0x70, 0xbf, 0x44, 0xff, 0x41, 0x56, 0x69, 0x7f, 0xd8, 0x84, 0xdc, 0x4d, 0xe7,
      0x29, 0xf6, 0x0a, 0xe6, 0x6b, 0x52, 0xc5, 0xbd, 0xf9, 0x59, 0x0d, 0x45, 0x9a, 0xf7, 0x36,
      0xa4, 0xc5, 0xd7, 0x2b, 0x82, 0x34, 0x9c, 0x88, 0x53, 0xa1, 0xea, 0x73, 0xe8, 0xae, 0x7f,
      0x56, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x33, 0x25, 0x5a, 0xb6, 0xba, 0xf7, 0x4c, 0x58, 0xaa, 0x56, 0x19, 0xc9, 0x8b, 0xe9, 0xf0,
      0xb9, 0x35, 0xe3, 0x44, 0x3b, 0xb2, 0x28, 0x9c, 0x0d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
      0x82, 0x05, 0xa0, 0x30, 0x82, 0x05, 0x9c, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
      0x16, 0x04, 0x14, 0x1d, 0xfc, 0x3f, 0xc5, 0x79, 0xff, 0xe5, 0x72, 0x49, 0x3e, 0x3b, 0x1c,
      0x1a, 0xb0, 0x47, 0xd4, 0x24, 0x03, 0x29, 0x05, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
      0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xd1, 0xbc, 0xdd, 0x59, 0x57, 0x90, 0xf1, 0xbb, 0xab,
      0x9b, 0x29, 0xcb, 0x16, 0x47, 0x60, 0x8c, 0x32, 0xdd, 0x47, 0xbc, 0x30, 0x81, 0xe1, 0x06,
      0x03, 0x55, 0x1d, 0x1f, 0x04, 0x81, 0xd9, 0x30, 0x81, 0xd6, 0x30, 0x81, 0xd3, 0xa0, 0x81,
      0xd0, 0xa0, 0x81, 0xcd, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x64, 0x70, 0x2f, 0x45, 0x2d,
      0x4d, 0x45, 0x25, 0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29,
      0x28, 0x33, 0x29, 0x2e, 0x63, 0x72, 0x6c, 0x86, 0x81, 0x9a, 0x6c, 0x64, 0x61, 0x70, 0x3a,
      0x2f, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x2f, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x6e, 0x3d, 0x45, 0x2d, 0x4d, 0x45,
      0x25, 0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33,
      0x29, 0x2c, 0x6f, 0x75, 0x3d, 0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0x61, 0x63,
      0x69, 0x6a, 0x61, 0x73, 0x25, 0x32, 0x30, 0x70, 0x61, 0x6b, 0x61, 0x6c, 0x70, 0x6f, 0x6a,
      0x75, 0x6d, 0x75, 0x25, 0x32, 0x30, 0x64, 0x61, 0x6c, 0x61, 0x2c, 0x6f, 0x3d, 0x45, 0x2d,
      0x4d, 0x45, 0x2c, 0x63, 0x3d, 0x6c, 0x76, 0x3f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
      0x63, 0x61, 0x74, 0x65, 0x72, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x6c,
      0x69, 0x73, 0x74, 0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
      0x63, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
      0x74, 0x69, 0x6f, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x82,
      0x01, 0x1b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x82, 0x01,
      0x0d, 0x30, 0x82, 0x01, 0x09, 0x30, 0x3a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x30, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x02, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
      0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x61, 0x69, 0x61, 0x2f, 0x45, 0x2d, 0x4d, 0x45, 0x25,
      0x32, 0x30, 0x53, 0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33, 0x29,
      0x2e, 0x63, 0x72, 0x74, 0x30, 0x81, 0x9b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x30, 0x02, 0x86, 0x81, 0x8e, 0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x65, 0x6d, 0x65,
      0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x6e, 0x3d, 0x45, 0x2d, 0x4d, 0x45, 0x25, 0x32, 0x30, 0x53,
      0x49, 0x25, 0x32, 0x30, 0x28, 0x43, 0x41, 0x31, 0x29, 0x28, 0x33, 0x29, 0x2c, 0x6f, 0x75,
      0x3d, 0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0x61, 0x63, 0x69, 0x6a, 0x61, 0x73,
      0x25, 0x32, 0x30, 0x70, 0x61, 0x6b, 0x61, 0x6c, 0x70, 0x6f, 0x6a, 0x75, 0x6d, 0x75, 0x25,
      0x32, 0x30, 0x64, 0x61, 0x6c, 0x61, 0x2c, 0x6f, 0x3d, 0x45, 0x2d, 0x4d, 0x45, 0x2c, 0x63,
      0x3d, 0x6c, 0x76, 0x3f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
      0x74, 0x65, 0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63,
      0x6c, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x61, 0x73, 0x73, 0x3d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
      0x6f, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x30, 0x2d, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x21, 0x68, 0x74, 0x74, 0x70, 0x73,
      0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f,
      0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x2e, 0x65, 0x6d, 0x65, 0x30, 0x0c,
      0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
      0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x06, 0xc0, 0x30, 0x3d,
      0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07, 0x04, 0x30, 0x30, 0x2e,
      0x06, 0x26, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x08, 0x84, 0xb5, 0x85, 0x50,
      0x85, 0xc0, 0x8d, 0x7d, 0x81, 0xf1, 0x91, 0x28, 0xe9, 0xa1, 0x06, 0x84, 0x8f, 0x95, 0x06,
      0x81, 0x14, 0x86, 0xcc, 0xd3, 0x05, 0x82, 0xc3, 0xde, 0x3b, 0x02, 0x01, 0x64, 0x02, 0x01,
      0x0b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x18, 0x30, 0x16, 0x06, 0x08, 0x2b,
      0x06, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
      0x0a, 0x03, 0x0c, 0x30, 0x82, 0x02, 0x88, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x82, 0x02,
      0x7f, 0x30, 0x82, 0x02, 0x7b, 0x30, 0x82, 0x02, 0x77, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
      0x01, 0x81, 0xfa, 0x3d, 0x01, 0x01, 0x01, 0x30, 0x82, 0x02, 0x66, 0x30, 0x82, 0x02, 0x38,
      0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x82, 0x02, 0x2a, 0x1e,
      0x82, 0x02, 0x26, 0x00, 0x53, 0x00, 0x69, 0x00, 0x73, 0x00, 0x20, 0x00, 0x73, 0x00, 0x65,
      0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00, 0x6b, 0x00, 0x61, 0x00,
      0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x69, 0x00, 0x72, 0x00, 0x20, 0x00, 0x69, 0x00, 0x65,
      0x00, 0x6b, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x75, 0x00, 0x74, 0x00, 0x73, 0x00, 0x20, 0x00,
      0x4c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x76, 0x00, 0x69, 0x00, 0x6a, 0x00, 0x61, 0x00, 0x73,
      0x00, 0x20, 0x00, 0x52, 0x00, 0x65, 0x00, 0x70, 0x00, 0x75, 0x00, 0x62, 0x00, 0x6c, 0x00,
      0x69, 0x00, 0x6b, 0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x73,
      0x00, 0x90, 0x00}},

    {{0x00, 0xb0, 0x05, 0xa8, 0xb5},
     {0x6e, 0x00, 0x69, 0x00, 0x65, 0x00, 0x67, 0x00, 0x74, 0x00, 0x61, 0x00, 0x20, 0x00, 0x70,
      0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x20, 0x00,
      0x61, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x65, 0x00, 0x63, 0x00, 0x69, 0x00, 0x6e,
      0x00, 0x6f, 0x00, 0x73, 0x00, 0x61, 0x00, 0x20, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x6b, 0x00,
      0x75, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x61, 0x00, 0x2e, 0x00, 0x20,
      0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00,
      0x6b, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x20, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x64,
      0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x73, 0x00, 0x20, 0x00, 0x56, 0x00, 0x41, 0x00,
      0x53, 0x00, 0x20, 0x00, 0x4c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x76, 0x00, 0x69, 0x00, 0x6a,
      0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00, 0x56, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x73, 0x00,
      0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x72, 0x00, 0x61, 0x00, 0x64, 0x00, 0x69, 0x00, 0x6f,
      0x00, 0x20, 0x00, 0x75, 0x00, 0x6e, 0x00, 0x20, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6c, 0x00,
      0x65, 0x90, 0x00}},

    {{0x00, 0xb0, 0x06, 0x5d, 0xb5},
     {0x00, 0x76, 0x00, 0x69, 0x00, 0x7a, 0x00, 0x69, 0x00, 0x6a, 0x00, 0x61, 0x00, 0x73, 0x00,
      0x20, 0x00, 0x63, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x72, 0x00, 0x73, 0x00, 0x20,
      0x00, 0x28, 0x00, 0x72, 0x00, 0x65, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x4e, 0x00, 0x72, 0x00,
      0x2e, 0x00, 0x34, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00, 0x30, 0x00, 0x31,
      0x00, 0x31, 0x00, 0x32, 0x00, 0x30, 0x00, 0x33, 0x00, 0x29, 0x00, 0x2c, 0x00, 0x20, 0x00,
      0x6e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6e,
      0x00, 0x6f, 0x00, 0x74, 0x00, 0x20, 0x00, 0x61, 0x00, 0x74, 0x00, 0x62, 0x00, 0x69, 0x00,
      0x6c, 0x00, 0x73, 0x00, 0x74, 0x00, 0x69, 0x00, 0x62, 0x00, 0x75, 0x00, 0x20, 0x00, 0x45,
      0x00, 0x6c, 0x00, 0x65, 0x00, 0x6b, 0x00, 0x74, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6e, 0x00,
      0x69, 0x00, 0x73, 0x00, 0x6b, 0x00, 0x6f, 0x00, 0x20, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x6b,
      0x00, 0x75, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x75, 0x00, 0x20, 0x00,
      0x6c, 0x00, 0x69, 0x00, 0x6b, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x20,
      0x00, 0x90, 0x00}},

    {{0x00, 0xb0, 0x07, 0x12, 0xb5},
     {0x75, 0x00, 0x6e, 0x00, 0x20, 0x00, 0x45, 0x00, 0x69, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x70,
      0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00, 0x72, 0x00, 0x6c, 0x00,
      0x61, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x61, 0x00, 0x20, 0x00, 0x64,
      0x00, 0x69, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6b, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00,
      0x61, 0x00, 0x69, 0x00, 0x20, 0x00, 0x31, 0x00, 0x39, 0x00, 0x39, 0x00, 0x39, 0x00, 0x2f,
      0x00, 0x39, 0x00, 0x33, 0x00, 0x2f, 0x00, 0x45, 0x00, 0x4b, 0x30, 0x28, 0x06, 0x08, 0x2b,
      0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
      0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x6d, 0x65, 0x2e, 0x6c, 0x76, 0x2f, 0x72, 0x65, 0x70,
      0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x30, 0x29, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04,
      0x01, 0x82, 0x37, 0x15, 0x0a, 0x04, 0x1c, 0x30, 0x1a, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
      0x82, 0x37, 0x0a, 0x03, 0x0c, 0x30, 0x22, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x01, 0x90, 0x00}},

    {{0x00, 0xb0, 0x07, 0xc7, 0xb5},
     {0x03, 0x04, 0x16, 0x30, 0x14, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x01,
      0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a,
      0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
      0xab, 0x81, 0x09, 0x26, 0x50, 0x7f, 0xbc, 0xa7, 0xcc, 0xad, 0x25, 0xc4, 0xf6, 0x8c, 0x88,
      0x9e, 0x61, 0xe7, 0x5e, 0x45, 0xf1, 0xbb, 0x6f, 0x7f, 0x95, 0x10, 0xf7, 0xf4, 0x20, 0xa6,
      0xc0, 0x4e, 0x38, 0x97, 0x22, 0x34, 0xa6, 0x9b, 0xea, 0x21, 0x08, 0xb3, 0x7a, 0xa0, 0x62,
      0x2f, 0xf9, 0xba, 0xfd, 0x01, 0xc2, 0xe8, 0x29, 0x1a, 0xf7, 0x4f, 0xd0, 0x63, 0x3d, 0xf7,
      0x31, 0xbd, 0x2c, 0x51, 0x5d, 0xc7, 0xeb, 0x42, 0x4f, 0x90, 0x7c, 0x6a, 0x95, 0x7f, 0x18,
      0xac, 0xf7, 0x6c, 0x36, 0xda, 0xe8, 0xd0, 0xe9, 0x45, 0xf0, 0xb2, 0x09, 0xc9, 0x50, 0x36,
      0xa7, 0x14, 0x0d, 0x77, 0xe9, 0x62, 0xf0, 0x3b, 0x3d, 0xae, 0xa5, 0xe6, 0x5a, 0x54, 0x9b,
      0x9a, 0xc4, 0x85, 0x5c, 0xcf, 0xdb, 0xf1, 0x83, 0x62, 0x83, 0xec, 0x6a, 0x78, 0x13, 0x17,
      0xf3, 0x7e, 0xe9, 0xfb, 0xd1, 0x13, 0xe9, 0xea, 0x9f, 0x2e, 0x3e, 0xf0, 0x16, 0xa2, 0xe0,
      0x33, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x08, 0x7c, 0x78},
     {0x6c, 0xbf, 0x6b, 0xba, 0x85, 0xcf, 0xed, 0x1f, 0x12, 0x4d, 0xd9, 0x90, 0x4d, 0xdf,
      0x17, 0x51, 0x26, 0xff, 0xe3, 0x4f, 0xf1, 0x77, 0x05, 0x12, 0xd9, 0xc9, 0x84, 0x24,
      0x1c, 0x85, 0xb7, 0x8a, 0xcc, 0x86, 0x8f, 0xfb, 0x93, 0xc2, 0x3e, 0x94, 0x1a, 0x41,
      0x4b, 0xe9, 0x94, 0x96, 0xb1, 0xf9, 0xf6, 0xa6, 0x58, 0x0a, 0x7e, 0xc9, 0xf3, 0xde,
      0x82, 0xa7, 0x93, 0x26, 0x58, 0xad, 0xc0, 0x39, 0xe1, 0x7e, 0x72, 0xaf, 0x97, 0x86,
      0x60, 0x0b, 0xe5, 0xeb, 0xbf, 0xc4, 0x6b, 0x7b, 0xbd, 0x25, 0xcb, 0xae, 0x36, 0x4d,
      0x2a, 0xbb, 0x11, 0xd9, 0xb2, 0x18, 0x4a, 0xf4, 0x6f, 0xa6, 0x40, 0x05, 0xbc, 0x9d,
      0x7e, 0x1f, 0x1f, 0x36, 0x5d, 0x88, 0x52, 0x5d, 0x49, 0x90, 0x69, 0xfb, 0xe0, 0x1e,
      0xed, 0x66, 0xea, 0xe4, 0x80, 0x89, 0x5d, 0x81, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xcb, 0x3f, 0xff, 0x0a, 0x4d, 0x08, 0x70, 0x06, 0xbf, 0x81, 0x01, 0x02, 0xa0, 0x80,
      0x00},
     {0x70, 0x1e, 0xbf, 0x81, 0x05, 0x1a, 0xa0, 0x18, 0x9a, 0x01, 0x03, 0x9b,
      0x01, 0x03, 0xa1, 0x10, 0x8c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0xff, 0x00,
      0x9c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0xff, 0x00, 0x90, 0x00}},

    // 3. Signing.
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x81}, {0x90, 0x00}},

    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x81, 0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x88, 0x00, 0x00, 0x33, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7,
      0x9f, 0xfd, 0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a, 0x3f, 0xae,
      0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a, 0x00},
     {0x94, 0xc3, 0x67, 0x6b, 0x8f, 0x07, 0xf7, 0xc0, 0x1d, 0x06, 0xa3, 0x7c, 0x36, 0x23, 0xa2,
      0x62, 0x53, 0x46, 0xb2, 0x0d, 0x51, 0xf2, 0x10, 0xce, 0x0a, 0x32, 0xff, 0x01, 0xc9, 0x40,
      0xfb, 0x27, 0x23, 0x58, 0x2a, 0x41, 0xa2, 0x1c, 0xb8, 0x58, 0x70, 0xc1, 0xa1, 0x4c, 0xda,
      0x64, 0x1a, 0xed, 0x03, 0x3e, 0x6a, 0xa3, 0xdc, 0xb5, 0x9c, 0xab, 0x6f, 0xd1, 0x27, 0x3d,
      0x46, 0x8d, 0xda, 0x9a, 0xc9, 0xd7, 0xc5, 0xbc, 0x65, 0x8c, 0x01, 0x85, 0xc2, 0x2e, 0x92,
      0x8a, 0xf3, 0xea, 0x2a, 0xfc, 0xbb, 0xd0, 0x3b, 0x4c, 0xd5, 0x19, 0x55, 0xd9, 0x92, 0x3e,
      0x8c, 0xbe, 0x10, 0xaa, 0x0f, 0xe4, 0x02, 0xe6, 0xc3, 0x05, 0x29, 0xf3, 0x6c, 0xa4, 0x96,
      0x6a, 0x44, 0xaf, 0xcc, 0xd7, 0x86, 0xd6, 0x85, 0xe1, 0x84, 0x71, 0x53, 0xec, 0x5c, 0x03,
      0xef, 0xde, 0xd3, 0x17, 0x4d, 0x3d, 0x2a, 0x3e, 0xaa, 0x11, 0x28, 0xba, 0x75, 0xa4, 0x05,
      0x8a, 0xf5, 0xdf, 0xcf, 0x83, 0xd8, 0x1b, 0xc2, 0x6e, 0x62, 0x80, 0x2e, 0xd6, 0xa0, 0x43,
      0x53, 0x51, 0xdd, 0x27, 0x7c, 0x4d, 0x78, 0x4c, 0xa2, 0x4f, 0x57, 0xaf, 0x5a, 0xd0, 0x37,
      0xb5, 0x85, 0xae, 0x56, 0xbd, 0x32, 0x3a, 0xb9, 0xa9, 0x75, 0x16, 0x4d, 0xa4, 0x89, 0x68,
      0x5b, 0x59, 0x9f, 0xec, 0x8b, 0xa1, 0xa0, 0x14, 0x71, 0xd1, 0xad, 0x7d, 0x8a, 0x36, 0x99,
      0x77, 0xd3, 0xe7, 0xcf, 0xf7, 0xeb, 0x35, 0x36, 0x32, 0x17, 0xb7, 0x27, 0x7b, 0x09, 0xab,
      0x7d, 0x97, 0xf1, 0xad, 0x8c, 0x22, 0x42, 0xdd, 0xb0, 0x9d, 0x16, 0x71, 0x6c, 0x1c, 0xe3,
      0xef, 0xcc, 0x75, 0x0a, 0xd7, 0x37, 0xd5, 0x02, 0x1d, 0x52, 0xce, 0x6a, 0x96, 0xaa, 0x2b,
      0xed, 0xce, 0xb4, 0xc2, 0x0a, 0x70, 0x9e, 0xaa, 0x28, 0xac, 0xaa, 0x1b, 0x34, 0x33, 0xba,
      0x87, 0x90, 0x00}}};
