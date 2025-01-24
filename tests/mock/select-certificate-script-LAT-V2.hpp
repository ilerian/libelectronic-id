/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
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

const PcscMock::ApduScript LATEID_IDEMIA_V2_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},

    // Select authentication certificate file.
    {{0x00, 0xA4, 0x09, 0x0C, 0x04, 0xAD, 0xF1, 0x34, 0x01}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x06, 0xc1, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x06, 0xc1, 0x30, 0x82, 0x04, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
      0x59, 0x79, 0xd9, 0x1f, 0xb8, 0x79, 0x21, 0x05, 0x5d, 0x5e, 0x8d, 0x2e, 0x6d, 0x8b, 0x82,
      0x16, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
      0x00, 0x30, 0x81, 0x83, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
      0x4c, 0x56, 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x30, 0x56, 0x41,
      0x53, 0x20, 0x4c, 0x61, 0x74, 0x76, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x56, 0x61, 0x6c, 0x73,
      0x74, 0x73, 0x20, 0x72, 0x61, 0x64, 0x69, 0x6f, 0x20, 0x75, 0x6e, 0x20, 0x74, 0x65, 0x6c,
      0x65, 0x76, 0xc4, 0xab, 0x7a, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x63, 0x65, 0x6e, 0x74, 0x72,
      0x73, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x61, 0x0c, 0x11, 0x4e, 0x54, 0x52,
      0x4c, 0x56, 0x2d, 0x34, 0x30, 0x30, 0x30, 0x33, 0x30, 0x31, 0x31, 0x32, 0x30, 0x33, 0x31,
      0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x44, 0x45, 0x4d, 0x4f, 0x20,
      0x4c, 0x56, 0x20, 0x65, 0x49, 0x44, 0x20, 0x49, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x37,
      0x30, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31, 0x32, 0x34, 0x30, 0x31, 0x34,
      0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x38, 0x32, 0x32, 0x31, 0x32, 0x33, 0x32, 0x31, 0x37,
      0x5a, 0x30, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4c,
      0x56, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x53, 0x45, 0x52,
      0x47, 0x45, 0x4a, 0x53, 0x20, 0x4b, 0x55, 0x4c, 0x49, 0xc5, 0xa0, 0x53, 0x31, 0x10, 0x30,
      0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x07, 0x4b, 0x55, 0x4c, 0x49, 0xc5, 0xa0, 0x53,
      0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c, 0x07, 0x53, 0x45, 0x52, 0x47,
      0x45, 0x4a, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x12, 0x50,
      0x4e, 0x4f, 0x4c, 0x56, 0x2d, 0x32, 0x31, 0x30, 0x38, 0x36, 0x30, 0x2d, 0x31, 0x30, 0x35,
      0x32, 0x38, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
      0x02, 0x82, 0x01, 0x01, 0x00, 0xd0, 0x37, 0xb8, 0xdf, 0x99, 0x3e, 0xbf, 0x7e, 0x51, 0xeb,
      0x9d, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x31, 0x8d, 0x07, 0x8c, 0x89, 0x18, 0xa8, 0x76, 0xf3, 0x20, 0x9d, 0xdf, 0x89, 0x9a, 0x20,
      0xbc, 0x57, 0x2f, 0x88, 0x0c, 0xa6, 0xd7, 0xbc, 0xbd, 0x36, 0xb1, 0x52, 0x4a, 0xd6, 0x25,
      0x0d, 0xd0, 0x44, 0x16, 0x17, 0x12, 0x57, 0xb7, 0x06, 0xbb, 0x4e, 0x89, 0xa8, 0x4a, 0xfd,
      0x3e, 0xac, 0x7c, 0x8d, 0x4a, 0x33, 0x0b, 0xcf, 0x38, 0x21, 0x34, 0x55, 0xbb, 0x73, 0x87,
      0x96, 0x26, 0x48, 0xb8, 0x7c, 0xbd, 0xb0, 0x3e, 0x83, 0x20, 0xca, 0x94, 0x2f, 0xae, 0xcc,
      0x08, 0x18, 0xb9, 0x14, 0xf2, 0x0d, 0x6d, 0x8b, 0x40, 0x5b, 0xb4, 0xe9, 0x0e, 0xc5, 0xfd,
      0xf8, 0x01, 0xa5, 0x5e, 0xfa, 0x63, 0xea, 0x7c, 0xe6, 0xa6, 0x4a, 0xc5, 0xa0, 0xbb, 0xaa,
      0x06, 0x85, 0xa7, 0xdb, 0x0d, 0x86, 0x15, 0x07, 0xba, 0x01, 0xac, 0xf3, 0x8d, 0x47, 0x8c,
      0x42, 0xdf, 0x5b, 0x7e, 0xbf, 0xed, 0x85, 0x10, 0x85, 0x6b, 0x4c, 0xcc, 0x32, 0x7b, 0x0e,
      0xa3, 0x92, 0xb2, 0x36, 0xba, 0x0e, 0x97, 0x41, 0x66, 0xbf, 0xf6, 0xb4, 0x18, 0x0b, 0x82,
      0x31, 0x81, 0xfa, 0x49, 0xb9, 0xbb, 0xa5, 0xfa, 0xb0, 0x54, 0x8d, 0x02, 0x02, 0xf1, 0xb1,
      0x67, 0x4c, 0x48, 0xea, 0x70, 0xc1, 0xa5, 0x95, 0x0d, 0x4b, 0x37, 0x3c, 0x8f, 0xc3, 0x5f,
      0x2a, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0xae, 0x09, 0x45, 0x12, 0x35, 0x6a, 0x70, 0x5e, 0xad, 0x1c, 0x06, 0xe1, 0x71, 0x22, 0x10,
      0x89, 0x73, 0xec, 0xda, 0x3b, 0xb2, 0xb2, 0xb0, 0x52, 0x3a, 0x64, 0x16, 0x7a, 0xce, 0xba,
      0xa8, 0x48, 0x2d, 0xff, 0xf4, 0xf3, 0x09, 0xd3, 0xd8, 0x37, 0xd2, 0x85, 0xa8, 0xee, 0xf8,
      0xd2, 0x93, 0xe2, 0x5b, 0xa9, 0x29, 0x59, 0x5e, 0x38, 0x04, 0x96, 0xd9, 0x5b, 0x0c, 0x88,
      0x90, 0xee, 0x9d, 0xe7, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x02, 0x49, 0x30, 0x82,
      0x02, 0x45, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30,
      0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
      0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
      0x07, 0x03, 0x04, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x6f,
      0x7c, 0x17, 0x36, 0x7d, 0xad, 0xde, 0xc4, 0xae, 0x9d, 0x15, 0x1a, 0x3e, 0xe8, 0x98, 0x86,
      0xae, 0xd7, 0xcb, 0xfc, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
      0x80, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x14, 0x8f, 0x68, 0xce, 0xbc, 0xe2, 0xc7, 0x40, 0x21, 0x53, 0x09, 0x42, 0xbb, 0xe5, 0x9e,
      0x1d, 0x8c, 0x4b, 0xcd, 0xbd, 0x38, 0x30, 0x81, 0xfb, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
      0x81, 0xf3, 0x30, 0x81, 0xf0, 0x30, 0x3b, 0x06, 0x06, 0x04, 0x00, 0x8f, 0x7a, 0x01, 0x02,
      0x30, 0x31, 0x30, 0x2f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16,
      0x23, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x70,
      0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x72, 0x65, 0x70, 0x6f,
      0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x30, 0x81, 0xb0, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04,
      0x01, 0x81, 0xfa, 0x3d, 0x02, 0x01, 0x02, 0x02, 0x30, 0x81, 0x9f, 0x30, 0x2f, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x23, 0x68, 0x74, 0x74, 0x70, 0x73,
      0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74,
      0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79,
      0x30, 0x6c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x60, 0x0c,
      0x5e, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0xc5, 0xa0, 0x69, 0x73, 0x20, 0x73, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0xc4, 0x81,
      0x74, 0x73, 0x20, 0x69, 0x72, 0x20, 0x69, 0x65, 0x6b, 0xc4, 0xbc, 0x61, 0x75, 0x74, 0x73,
      0x20, 0x4c, 0x61, 0x74, 0x76, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x52, 0x65, 0x70, 0x75, 0x62,
      0x6c, 0x69, 0x6b, 0x61, 0x73, 0x20, 0x69, 0x7a, 0x73, 0x6e, 0x69, 0x65, 0x67, 0x74, 0xc4,
      0x81, 0x20, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x75, 0x20, 0x61, 0x70, 0x6c, 0x69, 0x65,
      0x63, 0x69, 0x6e, 0x6f, 0xc5, 0xa1, 0xc4, 0x81, 0x20, 0x64, 0x6f, 0x6b, 0x75, 0x6d, 0x65,
      0x6e, 0x74, 0xc4, 0x81, 0x30, 0x7d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01,
      0x01, 0x04, 0x71, 0x30, 0x6f, 0x30, 0x42, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x30, 0x02, 0x86, 0x36, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x6d, 0x6f,
      0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x63,
      0x65, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x6d, 0x6f, 0x5f, 0x4c, 0x56, 0x5f, 0x65, 0x49, 0x44,
      0x5f, 0x49, 0x43, 0x41, 0x5f, 0x32, 0x30, 0x31, 0x37, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x29,
      0x06, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x1d, 0x68, 0x74, 0x74, 0x70,
      0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x65, 0x70, 0x2e, 0x65, 0x70,
      0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x30, 0x49, 0x06, 0x03, 0x55,
      0x1d, 0x1f, 0x04, 0x42, 0x30, 0x40, 0x30, 0x3e, 0xa0, 0x3c, 0xa0, 0x3a, 0x86, 0x38, 0x68,
      0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x65, 0x70, 0x61, 0x72,
      0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x64, 0x65,
      0x6d, 0x6f, 0x5f, 0x4c, 0x56, 0x5f, 0x65, 0x49, 0x44, 0x5f, 0x49, 0x43, 0x41, 0x5f, 0x32,
      0x30, 0x31, 0x37, 0x5f, 0x31, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a,
      0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00,
      0xa8, 0xf1, 0xb7, 0x43, 0xe3, 0xa5, 0x3d, 0xfa, 0x3e, 0xe6, 0xa5, 0x04, 0x0c, 0x6d, 0xcc,
      0x53, 0xc5, 0x0b, 0xaa, 0xc1, 0x68, 0x6f, 0x27, 0x7c, 0xbc, 0x50, 0x33, 0xec, 0xd0, 0x7f,
      0x49, 0x63, 0x61, 0x1e, 0x55, 0x39, 0x00, 0x6d, 0x21, 0xc5, 0xe0, 0x89, 0xbd, 0xe5, 0x74,
      0x18, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x87, 0x91, 0x8f, 0xf8, 0xba, 0xc5, 0xdc, 0xf4, 0x6d, 0x16, 0xb9, 0x54, 0x6a, 0xea, 0x00,
      0xa4, 0xe0, 0x94, 0x1b, 0x35, 0xd8, 0x7f, 0x9d, 0x8d, 0x73, 0xba, 0x44, 0x65, 0xc9, 0x8a,
      0x0d, 0x02, 0x7a, 0xb3, 0x59, 0x68, 0xc4, 0xd2, 0x53, 0x87, 0xdd, 0x12, 0xc8, 0xea, 0x62,
      0xe3, 0x21, 0x30, 0x20, 0x5e, 0xee, 0x87, 0x45, 0x16, 0x19, 0x98, 0xa8, 0x82, 0x32, 0x02,
      0x58, 0x82, 0x61, 0xa4, 0xc2, 0x57, 0x54, 0xae, 0x65, 0x9b, 0x8a, 0x3b, 0x84, 0x7c, 0xdf,
      0x61, 0xc7, 0xfb, 0xb4, 0x59, 0x14, 0x94, 0x8e, 0x21, 0x6c, 0x38, 0x39, 0x6f, 0x4f, 0xd1,
      0xa7, 0x77, 0xbf, 0xe6, 0x04, 0x76, 0x6f, 0x80, 0xfc, 0x9d, 0x85, 0x81, 0xda, 0x9e, 0x17,
      0xab, 0x29, 0xaf, 0x40, 0x47, 0xa9, 0x55, 0x31, 0x32, 0x6f, 0xd6, 0xa4, 0x0b, 0xe2, 0xd3,
      0x14, 0x5d, 0xb1, 0xac, 0x51, 0x2c, 0xab, 0x0c, 0x74, 0x09, 0x6c, 0xdf, 0xb9, 0xf0, 0xd7,
      0x3e, 0xe1, 0x25, 0xf7, 0xac, 0x3c, 0x89, 0x69, 0x80, 0x17, 0xd6, 0xd6, 0xf8, 0x80, 0x83,
      0x05, 0x09, 0x27, 0x16, 0x18, 0x8a, 0x12, 0xfd, 0x1e, 0x04, 0x0c, 0xaf, 0x64, 0xc2, 0xc0,
      0x58, 0xc2, 0x2c, 0x03, 0x70, 0x62, 0x09, 0x99, 0xfe, 0x67, 0xfe, 0x51, 0xcb, 0xce, 0xd7,
      0x26, 0x90, 0x00}},

    {{0x00, 0xb0, 0x05, 0xa8, 0xb5},
     {0xc0, 0x7c, 0xe1, 0x96, 0xd0, 0x4d, 0x36, 0x54, 0x10, 0x4a, 0x3f, 0x25, 0xd6, 0x85, 0xe7,
      0xdf, 0xa5, 0x33, 0x18, 0xc3, 0x77, 0xb0, 0xb0, 0xda, 0x92, 0xba, 0xe6, 0x36, 0x22, 0xee,
      0x74, 0x85, 0x87, 0x74, 0xe3, 0x38, 0xa3, 0x38, 0x1a, 0xbd, 0x6d, 0xde, 0xec, 0x85, 0xf9,
      0x22, 0xaf, 0xd2, 0x30, 0xe8, 0x39, 0x0c, 0x25, 0x57, 0x2f, 0x1b, 0x20, 0xa0, 0x7c, 0x88,
      0x9c, 0x99, 0x72, 0x9a, 0xc9, 0x78, 0xac, 0x24, 0xa2, 0xba, 0x95, 0xc6, 0xea, 0x11, 0xf4,
      0x78, 0x10, 0x83, 0x3d, 0x6d, 0x72, 0x86, 0x06, 0x92, 0xad, 0x6b, 0x64, 0x29, 0x9f, 0x93,
      0xd3, 0x48, 0x6a, 0xff, 0x5a, 0xdf, 0xec, 0xbf, 0xc4, 0x60, 0xa4, 0x40, 0x33, 0xae, 0x3a,
      0x30, 0xa2, 0xff, 0x5b, 0xa0, 0x87, 0x3d, 0x96, 0x26, 0x48, 0x91, 0x9b, 0x47, 0x2a, 0x5e,
      0x60, 0x79, 0x3b, 0x00, 0xf6, 0x60, 0x8c, 0x79, 0xf7, 0x24, 0x78, 0xe0, 0x17, 0xb2, 0x78,
      0x50, 0xa8, 0xef, 0x8c, 0x9b, 0xd3, 0xa1, 0x2f, 0xeb, 0xb7, 0xee, 0x8b, 0x03, 0x0f, 0x58,
      0x76, 0x73, 0xb0, 0xcb, 0x05, 0xe0, 0x56, 0xe6, 0x88, 0x7d, 0x95, 0x82, 0xf6, 0xb2, 0x9b,
      0x27, 0x73, 0x7f, 0x88, 0xad, 0xdd, 0x47, 0xea, 0x77, 0xa2, 0x23, 0xe3, 0x92, 0xcf, 0x23,
      0x26, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x06, 0x5d, 0x68},
     {0x7c, 0xdf, 0x98, 0xfb, 0x5d, 0x71, 0x04, 0x4c, 0xdf, 0xc8, 0x8a, 0x03, 0x94, 0xc3,
      0x1b, 0xdb, 0xe3, 0x0f, 0x2a, 0x6d, 0xa3, 0x9b, 0xcd, 0xa7, 0x09, 0x94, 0x09, 0x4c,
      0x29, 0xd8, 0xcb, 0x07, 0x47, 0x2a, 0x46, 0x9d, 0xcc, 0xdd, 0x1b, 0xb8, 0xd6, 0x19,
      0x14, 0x0a, 0x9a, 0xbb, 0x64, 0x84, 0x1a, 0xf8, 0x41, 0xf0, 0xb3, 0x3e, 0x0b, 0x95,
      0x52, 0x81, 0x03, 0xe6, 0x76, 0xe5, 0x8f, 0x26, 0x05, 0x3d, 0x1a, 0x6b, 0x5a, 0x2e,
      0x6c, 0x9d, 0xdd, 0x25, 0xf7, 0x26, 0x38, 0xd6, 0xdd, 0xe9, 0x66, 0x06, 0x86, 0xff,
      0x4c, 0x52, 0xbd, 0xc8, 0x83, 0xc5, 0xd4, 0x61, 0xe1, 0x08, 0xc3, 0x01, 0x4d, 0xd3,
      0x0c, 0xf5, 0x63, 0x15, 0xb5, 0x88, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xcb, 0x3f, 0xff, 0x0a, 0x4d, 0x08, 0x70, 0x06, 0xbf, 0x81, 0x01, 0x02, 0xa0, 0x80,
      0x00},
     {0x70, 0x1e, 0xbf, 0x81, 0x01, 0x1a, 0xa0, 0x18, 0x9a, 0x01, 0x03, 0x9b,
      0x01, 0x03, 0xa1, 0x10, 0x8c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0x43, 0x00,
      0x9c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0x43, 0x00, 0x90, 0x00}},

    // 3. Authenticate.
    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},

    // Detect if card is updated
    {{0x00, 0xA4, 0x02, 0x04, 0x02, 0x50, 0x31, 0x00}, {0x80, 0x02, 0x00, 0x08, 0x90, 0x00}},

    {{0x00, 0xB0, 0x00, 0x00, 0x08}, {0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x70, 0x01, 0x90, 0x00}},

    {{0x00, 0xA4, 0x02, 0x04, 0x02, 0x70, 0x01, 0x00}, {0x80, 0x02, 0x00, 0x05, 0x90, 0x00}},

    {{0x00, 0xB0, 0x00, 0x00, 0x05}, {0x30, 0x02, 0x02, 0x00, 0x81, 0x90, 0x00}},

    // Select AWP AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
      0x41, 0x57, 0x50},
     {0x90, 0x00}},

    // Set env
    {{0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x81}, {0x90, 0x00}},

    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x01, 0x0c, 0x31, 0x32, 0x33, 0x34, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff},
     {0x90, 0x00}},

    // Internal auth
    {{0x00, 0x88, 0x00, 0x00, 0x33, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7,
      0x9f, 0xfd, 0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a, 0x3f, 0xae,
      0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a, 0x00},
     {0x28, 0x78, 0xc0, 0x2d, 0x7f, 0x6f, 0x27, 0x48, 0x44, 0x08, 0x7a, 0x6f, 0xe2, 0x07, 0xd0,
      0x14, 0xab, 0x14, 0x4c, 0x72, 0x4b, 0x88, 0x3a, 0xee, 0xa1, 0x3c, 0x07, 0xc2, 0x63, 0x91,
      0xa0, 0xa3, 0x0c, 0x8e, 0xae, 0x32, 0x49, 0x85, 0x6f, 0xec, 0x2b, 0x3d, 0xeb, 0x9e, 0x66,
      0x87, 0x07, 0xe6, 0x18, 0x07, 0x64, 0x68, 0x38, 0xd6, 0x69, 0xbb, 0x47, 0x2a, 0x1a, 0x56,
      0x8d, 0x1d, 0xa0, 0xe9, 0xaf, 0x9a, 0x8b, 0x33, 0x4e, 0xab, 0x8d, 0x09, 0x77, 0x72, 0xb8,
      0x83, 0x92, 0x11, 0x5b, 0xd2, 0x45, 0x42, 0x5a, 0xc4, 0xf8, 0xfa, 0x04, 0xb7, 0xcd, 0x45,
      0x4a, 0xb9, 0x7e, 0xc9, 0x03, 0xe3, 0x86, 0x85, 0x51, 0xfa, 0x2b, 0x97, 0xd2, 0x82, 0x8f,
      0x05, 0x65, 0xfb, 0xfc, 0x2b, 0x97, 0xbe, 0xa3, 0xf1, 0xe6, 0x99, 0x91, 0x42, 0x99, 0xee,
      0x04, 0x15, 0x2c, 0xed, 0x48, 0x31, 0xa6, 0x72, 0x65, 0xd3, 0x03, 0x45, 0x21, 0x2c, 0x8a,
      0xdc, 0xd4, 0x6f, 0x06, 0xd9, 0x91, 0xa9, 0x8d, 0x38, 0x51, 0xbc, 0x57, 0xb0, 0xc0, 0xc6,
      0x2a, 0x5c, 0xeb, 0x7c, 0xb6, 0xf5, 0x01, 0x9c, 0xc8, 0xd4, 0xcb, 0xe5, 0x14, 0xc9, 0xe7,
      0xfb, 0xe8, 0x98, 0x95, 0x9c, 0xd6, 0x90, 0xe8, 0x89, 0x80, 0x5d, 0xe8, 0xe0, 0x54, 0xf0,
      0xf0, 0x91, 0xd5, 0x02, 0xee, 0xb5, 0x71, 0x05, 0x87, 0x60, 0xf6, 0xf3, 0x74, 0xb6, 0xa1,
      0x39, 0xb2, 0x8c, 0xe1, 0x26, 0x68, 0xa4, 0x2b, 0xd6, 0x0e, 0xe8, 0x4d, 0xc4, 0x16, 0x36,
      0x1b, 0xda, 0xbe, 0x2a, 0x47, 0x39, 0x8f, 0x01, 0x34, 0x86, 0x55, 0xea, 0x8d, 0xcd, 0xa4,
      0x93, 0x5b, 0x92, 0xde, 0x1d, 0xb9, 0x60, 0x10, 0x97, 0x48, 0xbe, 0xf7, 0x2b, 0x6e, 0xb6,
      0x1a, 0x00, 0xbe, 0x18, 0xa6, 0xae, 0x74, 0xca, 0xd0, 0x75, 0xd7, 0x0f, 0x21, 0x1e, 0x6f,
      0xd7, 0x90, 0x00}}};

const PcscMock::ApduScript LATEID_IDEMIA_V2_SELECT_SIGN_CERTIFICATE_AND_SIGNING {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
      0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
     {0x90, 0x00}},

    // Select signing certificate file.
    {{0x00, 0xA4, 0x09, 0x0C, 0x04, 0xAD, 0xF2, 0x34, 0x1F}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x08, 0x48, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x08, 0x48, 0x30, 0x82, 0x06, 0x30, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
      0x61, 0x93, 0x6c, 0xae, 0x52, 0xe7, 0x84, 0x96, 0x5d, 0x5e, 0x8d, 0x2e, 0x68, 0x4d, 0xbc,
      0x7a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
      0x00, 0x30, 0x81, 0x83, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
      0x4c, 0x56, 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x30, 0x56, 0x41,
      0x53, 0x20, 0x4c, 0x61, 0x74, 0x76, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x56, 0x61, 0x6c, 0x73,
      0x74, 0x73, 0x20, 0x72, 0x61, 0x64, 0x69, 0x6f, 0x20, 0x75, 0x6e, 0x20, 0x74, 0x65, 0x6c,
      0x65, 0x76, 0xc4, 0xab, 0x7a, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x63, 0x65, 0x6e, 0x74, 0x72,
      0x73, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x61, 0x0c, 0x11, 0x4e, 0x54, 0x52,
      0x4c, 0x56, 0x2d, 0x34, 0x30, 0x30, 0x30, 0x33, 0x30, 0x31, 0x31, 0x32, 0x30, 0x33, 0x31,
      0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x44, 0x45, 0x4d, 0x4f, 0x20,
      0x4c, 0x56, 0x20, 0x65, 0x49, 0x44, 0x20, 0x49, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x37,
      0x30, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31, 0x32, 0x34, 0x30, 0x31, 0x34,
      0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x38, 0x32, 0x32, 0x31, 0x32, 0x33, 0x32, 0x31, 0x37,
      0x5a, 0x30, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4c,
      0x56, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x53, 0x45, 0x52,
      0x47, 0x45, 0x4a, 0x53, 0x20, 0x4b, 0x55, 0x4c, 0x49, 0xc5, 0xa0, 0x53, 0x31, 0x10, 0x30,
      0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x07, 0x4b, 0x55, 0x4c, 0x49, 0xc5, 0xa0, 0x53,
      0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c, 0x07, 0x53, 0x45, 0x52, 0x47,
      0x45, 0x4a, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x12, 0x50,
      0x4e, 0x4f, 0x4c, 0x56, 0x2d, 0x32, 0x31, 0x30, 0x38, 0x36, 0x30, 0x2d, 0x31, 0x30, 0x35,
      0x32, 0x38, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
      0x02, 0x82, 0x01, 0x01, 0x00, 0xda, 0x96, 0xfc, 0x26, 0x03, 0xd1, 0x63, 0xfc, 0x96, 0xac,
      0x79, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x52, 0x6a, 0xbc, 0x9f, 0x54, 0xf7, 0x85, 0xac, 0x8a, 0xcf, 0xeb, 0xb5, 0x3e, 0xd3, 0x26,
      0x6f, 0x98, 0x61, 0x92, 0x6a, 0x3b, 0x42, 0x00, 0x74, 0x91, 0x69, 0xc9, 0xdc, 0xe0, 0x82,
      0xe9, 0x68, 0x8e, 0x47, 0x02, 0xb3, 0x82, 0x3e, 0x8e, 0xdd, 0xb9, 0x9b, 0xb4, 0x74, 0x91,
      0x4c, 0x06, 0x14, 0x32, 0x7a, 0x48, 0x38, 0xec, 0x8e, 0x09, 0x68, 0x90, 0x72, 0xbb, 0xf4,
      0xc6, 0x12, 0x6a, 0x80, 0x67, 0xb5, 0x38, 0x4a, 0x5e, 0xde, 0x83, 0x2e, 0x89, 0x48, 0x51,
      0x97, 0x9e, 0xcf, 0xce, 0xae, 0x00, 0xa5, 0x73, 0xb4, 0x29, 0x10, 0x7a, 0xbf, 0x0b, 0x11,
      0xa3, 0x2e, 0x49, 0x50, 0x20, 0x5d, 0x04, 0x86, 0x25, 0xf2, 0xb4, 0x60, 0x38, 0x7a, 0xcf,
      0xe7, 0x33, 0x94, 0x2f, 0x08, 0xcd, 0x9b, 0xe0, 0xea, 0x48, 0xd3, 0xdf, 0x89, 0x62, 0xd9,
      0xc8, 0xa2, 0xae, 0xd8, 0x68, 0x1a, 0xa7, 0xe4, 0xab, 0xf5, 0x5b, 0xc6, 0x4d, 0x79, 0x9d,
      0x64, 0xca, 0x85, 0x64, 0xc6, 0x40, 0x71, 0xef, 0x22, 0x62, 0xb1, 0x76, 0xd3, 0xb2, 0x05,
      0xe6, 0xe3, 0x55, 0x84, 0xfc, 0xfa, 0xc9, 0x0f, 0x84, 0x91, 0x33, 0xd1, 0x1d, 0xdc, 0x3e,
      0x30, 0xa2, 0xca, 0xe4, 0x0b, 0xe1, 0x08, 0xa6, 0xb1, 0x41, 0x8c, 0x70, 0x03, 0x04, 0x44,
      0x72, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0xe0, 0x97, 0x7f, 0x8a, 0x2f, 0xcc, 0x9f, 0xe5, 0xdf, 0x93, 0x7a, 0xb1, 0xea, 0xbc, 0x3b,
      0x8d, 0x78, 0x22, 0x51, 0x69, 0x20, 0x98, 0x01, 0x4b, 0x09, 0x96, 0x4a, 0x86, 0x5b, 0xa0,
      0x94, 0xd5, 0x1f, 0xc2, 0xe0, 0x16, 0x9b, 0xe9, 0x2f, 0x4e, 0x4c, 0x9b, 0x96, 0x1a, 0x76,
      0x3b, 0xf0, 0x70, 0xea, 0x1d, 0x1d, 0x58, 0xfd, 0x7e, 0x01, 0x44, 0x20, 0x55, 0x11, 0x99,
      0x6d, 0x7a, 0x40, 0x03, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x03, 0xd0, 0x30, 0x82,
      0x03, 0xcc, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30,
      0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
      0x06, 0x40, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x5c, 0x8d,
      0x2e, 0xd4, 0x2c, 0x74, 0xd5, 0x8d, 0x38, 0xf2, 0xba, 0x33, 0xee, 0x19, 0x26, 0x24, 0x12,
      0xc5, 0x95, 0xe1, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
      0x14, 0x8f, 0x68, 0xce, 0xbc, 0xe2, 0xc7, 0x40, 0x21, 0x53, 0x09, 0x42, 0xbb, 0xe5, 0x9e,
      0x1d, 0x8c, 0x4b, 0xcd, 0xbd, 0x38, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x18,
      0x30, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x16, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x0c, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x30, 0x82, 0x01, 0xd2, 0x06, 0x03, 0x55,
      0x1d, 0x20, 0x04, 0x82, 0x01, 0xc9, 0x30, 0x82, 0x01, 0xc5, 0x30, 0x3c, 0x06, 0x07, 0x04,
      0x00, 0x8b, 0xec, 0x40, 0x01, 0x02, 0x30, 0x31, 0x30, 0x2f, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x23, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
      0x77, 0x77, 0x77, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c,
      0x76, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x30, 0x82, 0x01,
      0x83, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xfa, 0x3d, 0x02, 0x01, 0x02, 0x02,
      0x30, 0x82, 0x01, 0x71, 0x30, 0x2f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x01, 0x16, 0x23, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
      0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x72, 0x65,
      0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x30, 0x82, 0x01, 0x3c, 0x06, 0x08, 0x2b,
      0x06, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x82, 0x01, 0x2e, 0x0c, 0x82, 0x01, 0x2a, 0xc5,
      0xa0, 0x69, 0x73, 0x20, 0x73, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0xc4, 0x81, 0x74,
      0x73, 0x20, 0x69, 0x72, 0x20, 0x69, 0x65, 0x6b, 0xc4, 0xbc, 0x61, 0x75, 0x74, 0x73, 0x20,
      0x4c, 0x61, 0x74, 0x76, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x52, 0x65, 0x70, 0x75, 0x62, 0x6c,
      0x69, 0x6b, 0x61, 0x73, 0x20, 0x69, 0x7a, 0x73, 0x6e, 0x69, 0x65, 0x67, 0x74, 0xc4, 0x81,
      0x20, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x75, 0x20, 0x61, 0x70, 0x6c, 0x69, 0x65, 0x63,
      0x69, 0x6e, 0x6f, 0xc5, 0xa1, 0xc4, 0x81, 0x20, 0x64, 0x6f, 0x6b, 0x75, 0x6d, 0x65, 0x6e,
      0x74, 0xc4, 0x81, 0x2e, 0x20, 0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0xc4, 0x81,
      0x74, 0x75, 0x20, 0x69, 0x7a, 0x64, 0x65, 0x76, 0x69, 0x73, 0x20, 0x56, 0x41, 0x53, 0x20,
      0x4c, 0x61, 0x74, 0x76, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x56, 0x61, 0x6c, 0x73, 0x74, 0x73,
      0x20, 0x72, 0x61, 0x64, 0x69, 0x6f, 0x20, 0x75, 0x6e, 0x20, 0x74, 0x65, 0x6c, 0x65, 0x76,
      0xc4, 0xab, 0x7a, 0x69, 0x6a, 0x61, 0x73, 0x20, 0x63, 0x65, 0x6e, 0x74, 0x72, 0x73, 0x20,
      0x28, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x72, 0x65, 0xc4, 0xa3, 0x2e, 0x4e, 0x72, 0x2e, 0x20, 0x34, 0x30, 0x30, 0x30, 0x33, 0x30,
      0x31, 0x31, 0x32, 0x30, 0x33, 0x29, 0x2c, 0x20, 0x6e, 0x6f, 0x64, 0x72, 0x6f, 0xc5, 0xa1,
      0x69, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x74, 0x62, 0x69, 0x6c, 0x73, 0x74, 0xc4, 0xab, 0x62,
      0x75, 0x20, 0x45, 0x6c, 0x65, 0x6b, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x73, 0x6b, 0x6f, 0x20,
      0x64, 0x6f, 0x6b, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x75, 0x20, 0x6c, 0x69, 0x6b, 0x75, 0x6d,
      0x61, 0x6d, 0x20, 0x75, 0x6e, 0x20, 0x45, 0x69, 0x72, 0x6f, 0x70, 0x61, 0x73, 0x20, 0x50,
      0x61, 0x72, 0x6c, 0x61, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x20, 0x75, 0x6e, 0x20, 0x50, 0x61,
      0x64, 0x6f, 0x6d, 0x65, 0x73, 0x20, 0x72, 0x65, 0x67, 0x75, 0x6c, 0x61, 0x69, 0x20, 0x4e,
      0x72, 0x2e, 0x20, 0x39, 0x31, 0x30, 0x2f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x7d, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x71, 0x30, 0x6f, 0x30, 0x42, 0x06,
      0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x36, 0x68, 0x74, 0x74, 0x70,
      0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73,
      0x74, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x6d, 0x6f, 0x5f,
      0x4c, 0x56, 0x5f, 0x65, 0x49, 0x44, 0x5f, 0x49, 0x43, 0x41, 0x5f, 0x32, 0x30, 0x31, 0x37,
      0x2e, 0x63, 0x72, 0x74, 0x30, 0x29, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
      0x01, 0x86, 0x1d, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e,
      0x70, 0x72, 0x65, 0x70, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e,
      0x6c, 0x76, 0x30, 0x81, 0xaa, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03,
      0x04, 0x81, 0x9d, 0x30, 0x81, 0x9a, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01,
      0x01, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x04, 0x30, 0x13, 0x06, 0x06,
      0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x30, 0x09, 0x06, 0x07, 0x04, 0x00, 0x8e, 0x46, 0x01,
      0x06, 0x01, 0x30, 0x15, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x02, 0x30,
      0x09, 0x06, 0x07, 0x04, 0x00, 0x8b, 0xec, 0x49, 0x01, 0x01, 0x30, 0x58, 0x06, 0x06, 0x04,
      0x00, 0x8e, 0x46, 0x01, 0x05, 0x30, 0x4e, 0x30, 0x25, 0x16, 0x1f, 0x68, 0x74, 0x74, 0x70,
      0x73, 0x90, 0x00}},

    {{0x00, 0xb0, 0x05, 0xa8, 0xb5},
     {0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74,
      0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x65, 0x6e, 0x2f, 0x70, 0x64, 0x73, 0x13, 0x02, 0x65, 0x6e,
      0x30, 0x25, 0x16, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
      0x2e, 0x65, 0x70, 0x61, 0x72, 0x61, 0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x6c,
      0x76, 0x2f, 0x70, 0x64, 0x73, 0x13, 0x02, 0x6c, 0x76, 0x30, 0x49, 0x06, 0x03, 0x55, 0x1d,
      0x1f, 0x04, 0x42, 0x30, 0x40, 0x30, 0x3e, 0xa0, 0x3c, 0xa0, 0x3a, 0x86, 0x38, 0x68, 0x74,
      0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x65, 0x70, 0x61, 0x72, 0x61,
      0x6b, 0x73, 0x74, 0x73, 0x2e, 0x6c, 0x76, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x64, 0x65, 0x6d,
      0x6f, 0x5f, 0x4c, 0x56, 0x5f, 0x65, 0x49, 0x44, 0x5f, 0x49, 0x43, 0x41, 0x5f, 0x32, 0x30,
      0x31, 0x37, 0x5f, 0x31, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
      0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x06,
      0xd1, 0xc9, 0xc4, 0xc7, 0x98, 0x72, 0x1d, 0x7d, 0xee, 0xf9, 0x11, 0xce, 0xcd, 0xf9, 0xae,
      0x6c, 0x90, 0x00}},

    {{0x00, 0xb0, 0x06, 0x5d, 0xb5},
     {0xd0, 0xfd, 0x85, 0xc9, 0xef, 0xe9, 0x23, 0xf8, 0xa1, 0xf9, 0x7c, 0x00, 0x3d, 0x01, 0xdf,
      0x54, 0xa0, 0xbd, 0xfe, 0xd6, 0xff, 0x4c, 0xda, 0x40, 0x24, 0x35, 0x39, 0xc7, 0xc3, 0x6a,
      0x46, 0x83, 0x5c, 0xe9, 0x59, 0xb9, 0xda, 0x25, 0x26, 0x4c, 0xf0, 0x30, 0xed, 0xbc, 0x8d,
      0xd6, 0x2f, 0x2b, 0x88, 0xd1, 0x2d, 0xad, 0x3a, 0xdf, 0x95, 0x19, 0x6a, 0x0b, 0x6b, 0x37,
      0x47, 0x51, 0xce, 0x4b, 0x73, 0xe7, 0x29, 0x45, 0xd6, 0x90, 0x1f, 0x82, 0xd3, 0x26, 0x35,
      0x1c, 0x98, 0x4d, 0x95, 0xea, 0x7e, 0x56, 0x5d, 0x3a, 0x72, 0xa6, 0x17, 0x47, 0xb2, 0xd9,
      0x44, 0x68, 0x58, 0xcb, 0xb9, 0xb2, 0xfc, 0x34, 0x28, 0xb1, 0xb2, 0x4f, 0x02, 0xda, 0x8d,
      0x9f, 0xe4, 0x30, 0x5d, 0xa5, 0xec, 0x1d, 0x1d, 0xaa, 0x7c, 0x8f, 0x09, 0x13, 0xf8, 0xa4,
      0xf4, 0x88, 0x40, 0xd9, 0xea, 0x5a, 0xfe, 0x9d, 0x35, 0x2c, 0x72, 0x77, 0xcc, 0x07, 0xa3,
      0x5c, 0x09, 0xf7, 0x8a, 0xb5, 0xcb, 0x1c, 0x23, 0x67, 0x6c, 0x24, 0x72, 0xb0, 0x15, 0xbf,
      0x1c, 0x5a, 0x16, 0x91, 0xea, 0xcd, 0xd6, 0x42, 0xad, 0x22, 0xdc, 0xeb, 0xb9, 0xbb, 0x61,
      0x7e, 0x1c, 0x09, 0xa1, 0x5f, 0xb4, 0x5d, 0x0e, 0x78, 0xb0, 0xbb, 0xdd, 0x00, 0x91, 0x2a,
      0x88, 0x90, 0x00}},

    {{0x00, 0xb0, 0x07, 0x12, 0xb5},
     {0xef, 0xf8, 0x76, 0xfe, 0x2d, 0x31, 0x84, 0xf5, 0x0e, 0x04, 0xf6, 0x80, 0xb3, 0x9e, 0x97,
      0xda, 0xa5, 0xc1, 0x51, 0x8c, 0x44, 0x4f, 0x8b, 0x80, 0xb3, 0x46, 0x8b, 0x99, 0xb1, 0x4e,
      0xdf, 0x77, 0xe0, 0x6a, 0x6c, 0x9e, 0x89, 0x02, 0xe3, 0x17, 0x99, 0x8a, 0x11, 0x8a, 0x04,
      0x51, 0xfa, 0x00, 0x96, 0xa2, 0xd7, 0x94, 0x4b, 0x3a, 0x0e, 0x3d, 0x37, 0x95, 0x3b, 0x95,
      0x16, 0x75, 0x46, 0xfb, 0xce, 0xc0, 0xda, 0x9f, 0xc5, 0x1a, 0xf4, 0x86, 0x86, 0x3f, 0xba,
      0xdf, 0x22, 0x9a, 0xb3, 0xd2, 0xb3, 0xea, 0x9d, 0xe4, 0xbe, 0x9f, 0x91, 0xce, 0xae, 0x7c,
      0x30, 0xed, 0x4e, 0xdf, 0x8e, 0x80, 0xef, 0x70, 0xbf, 0x61, 0x46, 0x08, 0xdf, 0x00, 0x0a,
      0xde, 0x44, 0xbf, 0xdf, 0x4b, 0xcc, 0x1c, 0xc9, 0xb3, 0x56, 0xc6, 0xfd, 0xec, 0x4d, 0x66,
      0x85, 0x80, 0xca, 0x42, 0x03, 0x94, 0xea, 0x54, 0x01, 0x7c, 0x1e, 0xd5, 0x29, 0xce, 0xf4,
      0x3b, 0x7e, 0x8c, 0x1e, 0xb6, 0x51, 0xec, 0xe1, 0x4d, 0x2e, 0xd8, 0x56, 0x90, 0x3c, 0x39,
      0xeb, 0xd7, 0x80, 0x47, 0x93, 0x95, 0x68, 0x8c, 0xcd, 0x3f, 0x55, 0xc7, 0xca, 0x5d, 0xc3,
      0x46, 0x73, 0x82, 0xaa, 0x9d, 0xf7, 0xb5, 0x71, 0x82, 0x9c, 0x5d, 0xcb, 0x1e, 0x0d, 0xe9,
      0x2d, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x07, 0xc7, 0x85},
     {0xff, 0xfa, 0x6e, 0x60, 0x2b, 0x4b, 0x48, 0x49, 0xa9, 0xd4, 0x66, 0xd8, 0x6e, 0xfe, 0x3c,
      0x28, 0x3a, 0x01, 0x1f, 0xd2, 0xd1, 0xe9, 0x3f, 0x8e, 0xe2, 0xce, 0x0e, 0xdd, 0x07, 0x63,
      0x5b, 0xe5, 0x71, 0xe7, 0xd9, 0x41, 0xb6, 0xd0, 0x3a, 0x46, 0x0f, 0x3a, 0x00, 0xd9, 0x50,
      0x85, 0x04, 0x37, 0xdd, 0x8c, 0x41, 0xe1, 0xe7, 0x51, 0xff, 0x20, 0x17, 0xbc, 0x98, 0xb3,
      0x11, 0x07, 0x69, 0xa2, 0x86, 0x83, 0x87, 0x9c, 0x4c, 0x84, 0xf2, 0xe6, 0x92, 0xbc, 0xa0,
      0xe3, 0xca, 0x8a, 0xe2, 0x51, 0xdc, 0x12, 0x78, 0x2c, 0x1c, 0x98, 0x35, 0x3f, 0xb4, 0x9d,
      0xa6, 0x81, 0xac, 0x74, 0x0e, 0xd8, 0x00, 0xef, 0x06, 0xf0, 0x12, 0xd7, 0xd9, 0xdb, 0xea,
      0xfc, 0x72, 0xe6, 0x84, 0x56, 0x68, 0x26, 0x46, 0xf4, 0x54, 0x97, 0xbb, 0xca, 0x51, 0x15,
      0x18, 0x00, 0x9e, 0xb2, 0x82, 0xb2, 0x9e, 0x4d, 0xb4, 0xc7, 0x4e, 0x1e, 0x08, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select QSCD AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0x51, 0x53, 0x43, 0x44, 0x20, 0x41,
      0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E},
     {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xcb, 0x3f, 0xff, 0x0a, 0x4d, 0x08, 0x70, 0x06, 0xbf, 0x81, 0x05, 0x02, 0xa0, 0x80,
      0x00},
     {0x70, 0x1e, 0xbf, 0x81, 0x05, 0x1a, 0xa0, 0x18, 0x9a, 0x01, 0x03, 0x9b,
      0x01, 0x03, 0xa1, 0x10, 0x8c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0xff, 0x00,
      0x9c, 0x06, 0xf3, 0x00, 0x00, 0x73, 0xff, 0x00, 0x90, 0x00}},

    // 3. Signing.
    // Select QSCD AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0x51, 0x53, 0x43, 0x44, 0x20, 0x41,
      0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E},
     {0x90, 0x00}},

    // Detect if card is updated
    {{0x00, 0xA4, 0x02, 0x04, 0x02, 0x50, 0x31, 0x00}, {0x80, 0x02, 0x00, 0x08, 0x90, 0x00}},

    {{0x00, 0xB0, 0x00, 0x00, 0x08}, {0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0x70, 0x01, 0x90, 0x00}},

    {{0x00, 0xA4, 0x02, 0x04, 0x02, 0x70, 0x01, 0x00}, {0x80, 0x02, 0x00, 0x05, 0x90, 0x00}},

    {{0x00, 0xB0, 0x00, 0x00, 0x05}, {0x30, 0x02, 0x02, 0x00, 0x9F, 0x90, 0x00}},

    // Select QSCD AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x10, 0x51, 0x53, 0x43, 0x44, 0x20, 0x41,
      0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x9f}, {0x90, 0x00}},

    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x85, 0x0c, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x2a, 0x9e, 0x9a, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7, 0x9f, 0xfd,
      0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a, 0x3f, 0xae,
      0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a, 0x00},
     {0x80, 0x74, 0x47, 0xb8, 0x19, 0xf2, 0x79, 0x5f, 0x0b, 0x21, 0x13, 0x11, 0x8e, 0x80, 0xb5,
      0x34, 0x60, 0x8b, 0x01, 0x9b, 0x1f, 0x17, 0x3e, 0xbc, 0x4f, 0xa3, 0x9f, 0x67, 0xe0, 0xb6,
      0xa0, 0x26, 0x66, 0xd1, 0x13, 0x44, 0x3b, 0xca, 0x24, 0xa8, 0xf6, 0xf6, 0x47, 0x03, 0x53,
      0x31, 0x9d, 0x73, 0x77, 0xcd, 0x1b, 0x1c, 0xaa, 0x12, 0xf4, 0x24, 0x59, 0x3d, 0x07, 0xb3,
      0xe9, 0x20, 0x12, 0x75, 0x97, 0xd9, 0xda, 0x5a, 0x56, 0x3c, 0xbd, 0x35, 0xd6, 0xed, 0x2b,
      0x0d, 0xdc, 0x5b, 0x01, 0xfd, 0xaf, 0x2c, 0x00, 0x1e, 0x90, 0x1c, 0x6b, 0x27, 0x97, 0xf1,
      0xde, 0x1b, 0x2d, 0x5f, 0x26, 0x0c, 0x44, 0x22, 0xca, 0x8b, 0x57, 0x97, 0x68, 0xcb, 0xb8,
      0xbc, 0xf1, 0x0e, 0xb6, 0x58, 0x26, 0x1e, 0xfb, 0x41, 0x83, 0x25, 0x20, 0xc6, 0x89, 0x0d,
      0xcf, 0xb7, 0xfa, 0x22, 0x3e, 0xa1, 0xf1, 0x8c, 0xfc, 0xf3, 0x1b, 0xbd, 0x48, 0x1c, 0xc0,
      0x79, 0x18, 0x43, 0x64, 0x9e, 0x15, 0x98, 0x45, 0x90, 0x23, 0x29, 0x91, 0xf5, 0x6c, 0xea,
      0xa8, 0x31, 0xc3, 0x03, 0x9d, 0x6b, 0xfd, 0x13, 0xc9, 0xe2, 0xc1, 0xc5, 0x4c, 0xcd, 0x88,
      0x29, 0x4e, 0x7d, 0xba, 0x6c, 0x08, 0x43, 0x5e, 0xf5, 0xb0, 0x87, 0xac, 0x50, 0x16, 0x41,
      0x66, 0xdb, 0xa3, 0x87, 0x87, 0x0c, 0xdb, 0x0f, 0xe6, 0xad, 0x1f, 0xe6, 0x32, 0xba, 0x39,
      0x3e, 0xd1, 0x7d, 0xdc, 0xc6, 0xf9, 0x61, 0x55, 0xcb, 0x9e, 0x08, 0xe4, 0xef, 0xef, 0x42,
      0xe4, 0x19, 0xa4, 0x0d, 0xa8, 0x93, 0x7c, 0x1f, 0xd6, 0x70, 0x68, 0x6c, 0x63, 0x8a, 0x44,
      0xe2, 0xb0, 0x23, 0xfe, 0xff, 0xb4, 0xc1, 0x01, 0xf0, 0x96, 0xa6, 0x2c, 0x8e, 0x6a, 0x3e,
      0xd7, 0xa9, 0xa8, 0xeb, 0x9b, 0x59, 0xa4, 0x1d, 0xf4, 0x1e, 0x26, 0x70, 0xe3, 0xd9, 0x12,
      0xf5, 0x90, 0x00}}};
