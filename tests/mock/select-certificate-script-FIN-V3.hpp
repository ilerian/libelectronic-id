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

const PcscMock::ApduScript FINEID_V3_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE = {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d,
      0x31, 0x35},
     {0x90, 0x00}},
    // Select authentication certificate file.
    {{0x00, 0xA4, 0x08, 0x0C, 0x02, 0x43, 0x31}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x06, 0x7c, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x06, 0x7c, 0x30, 0x82, 0x04, 0x64, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04,
      0x06, 0x05, 0x40, 0x44, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
      0x01, 0x0b, 0x05, 0x00, 0x30, 0x74, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
      0x13, 0x02, 0x46, 0x49, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x1a,
      0x56, 0x61, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x6b, 0x69, 0x73, 0x74, 0x65, 0x72, 0x69,
      0x6b, 0x65, 0x73, 0x6b, 0x75, 0x73, 0x20, 0x54, 0x45, 0x53, 0x54, 0x31, 0x18, 0x30, 0x16,
      0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0f, 0x54, 0x65, 0x73, 0x74, 0x69, 0x76, 0x61, 0x72,
      0x6d, 0x65, 0x6e, 0x74, 0x65, 0x65, 0x74, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04,
      0x03, 0x13, 0x1d, 0x56, 0x52, 0x4b, 0x20, 0x43, 0x41, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x54,
      0x65, 0x73, 0x74, 0x20, 0x50, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x73, 0x20, 0x2d, 0x20,
      0x47, 0x33, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x36, 0x30, 0x32, 0x31, 0x31, 0x30,
      0x32, 0x30, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x35, 0x32, 0x32, 0x32, 0x30, 0x35,
      0x39, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x35, 0x39, 0x5a, 0x30, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x46, 0x49, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x09, 0x39,
      0x39, 0x39, 0x30, 0x30, 0x33, 0x33, 0x35, 0x45, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
      0x04, 0x2a, 0x13, 0x05, 0x4c, 0x49, 0x49, 0x53, 0x41, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
      0x55, 0x04, 0x04, 0x13, 0x0f, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x4e,
      0x49, 0x53, 0x59, 0x4a, 0x55, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
      0x1f, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x4e, 0x49, 0x53, 0x59, 0x4a,
      0x55, 0x20, 0x4c, 0x49, 0x49, 0x53, 0x41, 0x20, 0x39, 0x39, 0x39, 0x30, 0x30, 0x33, 0x33,
      0x35, 0x45, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
      0x02, 0x82, 0x01, 0x01, 0x00, 0xa4, 0x60, 0x92, 0x7d, 0x46, 0x97, 0xe3, 0xf0, 0x3b, 0xd7,
      0x88, 0x1a, 0x36, 0xb8, 0xac, 0xe3, 0xb6, 0x74, 0xce, 0x7a, 0xde, 0xd9, 0xff, 0x48, 0x87,
      0x7a, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x46, 0x60, 0x23, 0x5c, 0xcb, 0x9c, 0xb9, 0x30, 0x25, 0xce, 0x4f, 0x26, 0x71, 0xc3, 0x3b,
      0x43, 0x9a, 0xf3, 0x33, 0xb0, 0xb9, 0xfb, 0x39, 0x30, 0xb8, 0x59, 0x67, 0xc9, 0x15, 0x13,
      0x5e, 0xb4, 0xa2, 0x32, 0xe2, 0x50, 0xf8, 0x34, 0xd2, 0x47, 0x8a, 0x5b, 0x0a, 0x2a, 0xf6,
      0x40, 0xf5, 0xd7, 0xb1, 0xe3, 0x21, 0xa3, 0xbb, 0xa8, 0x97, 0x78, 0x38, 0x6e, 0x0a, 0xb8,
      0x89, 0xbb, 0xd6, 0x48, 0x15, 0x41, 0x4e, 0x98, 0xdb, 0xac, 0xed, 0x27, 0x7c, 0x2c, 0xf4,
      0xf2, 0xf8, 0x16, 0x99, 0x2b, 0xfb, 0xc8, 0xe3, 0x37, 0x6e, 0x32, 0xdf, 0x06, 0x8a, 0xc6,
      0x20, 0x2b, 0x4c, 0xa6, 0xc8, 0xd9, 0xb9, 0xb5, 0xad, 0xce, 0xbf, 0x74, 0xef, 0x55, 0x8f,
      0x15, 0x69, 0xb5, 0x06, 0x11, 0x40, 0xfa, 0x4e, 0xbe, 0xa9, 0x0f, 0x54, 0x25, 0xa3, 0x4f,
      0x69, 0xac, 0xb1, 0x47, 0x39, 0xb5, 0xcd, 0x3b, 0xb0, 0x0d, 0x51, 0xd8, 0x96, 0xad, 0xa3,
      0x23, 0xc1, 0xc3, 0x69, 0x14, 0x4c, 0x5e, 0x37, 0x39, 0x97, 0x24, 0x4f, 0x81, 0x94, 0xc5,
      0xdf, 0x94, 0x45, 0xf0, 0x15, 0x70, 0xe0, 0xfe, 0xdf, 0x0e, 0x31, 0x88, 0x4f, 0x78, 0x16,
      0xe1, 0xe5, 0xcf, 0x14, 0xe8, 0x7e, 0x77, 0x4a, 0xe4, 0x12, 0x94, 0x69, 0x21, 0x9e, 0xbc,
      0x1d, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x59, 0x85, 0xf5, 0x14, 0xb1, 0x19, 0xa4, 0x6a, 0x1c, 0x66, 0x2c, 0x2f, 0xed, 0x02, 0x6b,
      0xea, 0xe4, 0xd4, 0xc5, 0x65, 0xc5, 0xf9, 0xac, 0x3f, 0x55, 0x64, 0xf6, 0x10, 0x17, 0x67,
      0xa9, 0x69, 0xc3, 0x04, 0xb2, 0x58, 0x62, 0xca, 0x35, 0xb4, 0x31, 0x9a, 0x7f, 0xcc, 0x5b,
      0x9b, 0xd3, 0x36, 0xb5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x02, 0x13, 0x30, 0x82,
      0x02, 0x0f, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
      0x5b, 0xce, 0x86, 0x9c, 0xc7, 0x53, 0x43, 0xe6, 0x02, 0xb9, 0xfb, 0x71, 0x6c, 0x8c, 0x6d,
      0xa3, 0x20, 0xe5, 0xb1, 0xf8, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
      0x14, 0x82, 0x5d, 0xe9, 0x5c, 0xd3, 0x32, 0x46, 0x09, 0xcf, 0xd2, 0x6f, 0x0a, 0x86, 0xe9,
      0x0a, 0xe8, 0xad, 0xc9, 0x24, 0xe5, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
      0xff, 0x04, 0x04, 0x03, 0x02, 0x04, 0xb0, 0x30, 0x81, 0xcd, 0x06, 0x03, 0x55, 0x1d, 0x20,
      0x04, 0x81, 0xc5, 0x30, 0x81, 0xc2, 0x30, 0x81, 0xbf, 0x06, 0x09, 0x2a, 0x81, 0x76, 0x84,
      0x05, 0x63, 0x0a, 0x20, 0x01, 0x30, 0x81, 0xb1, 0x30, 0x27, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x05, 0x07, 0x02, 0x01, 0x16, 0x1b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70, 0x73,
      0x39, 0x39, 0x2f, 0x30, 0x81, 0x85, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x02, 0x30, 0x79, 0x1a, 0x77, 0x56, 0x61, 0x72, 0x6d, 0x65, 0x6e, 0x6e, 0x65, 0x70, 0x6f,
      0x6c, 0x69, 0x74, 0x69, 0x69, 0x6b, 0x6b, 0x61, 0x20, 0x6f, 0x6e, 0x20, 0x73, 0x61, 0x61,
      0x74, 0x61, 0x76, 0x69, 0x6c, 0x6c, 0x61, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
      0x66, 0x69, 0x6b, 0x61, 0x74, 0x20, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x66, 0x69,
      0x6e, 0x6e, 0x73, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
      0x74, 0x65, 0x20, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x69, 0x73, 0x20, 0x61, 0x76,
      0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
      0x77, 0x77, 0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63,
      0x70, 0x73, 0x39, 0x39, 0x30, 0x33, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x2c, 0x30, 0x2a,
      0x81, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x28, 0x47, 0x33, 0x74, 0x65, 0x73, 0x74, 0x69, 0x4c, 0x69, 0x69, 0x73, 0x61, 0x30, 0x31,
      0x36, 0x2e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x6e, 0x69, 0x73, 0x79,
      0x6a, 0x75, 0x40, 0x74, 0x65, 0x73, 0x74, 0x69, 0x2e, 0x66, 0x69, 0x30, 0x0f, 0x06, 0x03,
      0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x37,
      0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x30, 0x30, 0x2e, 0x30, 0x2c, 0xa0, 0x2a, 0xa0, 0x28,
      0x86, 0x26, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
      0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x76,
      0x72, 0x6b, 0x74, 0x70, 0x33, 0x63, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x6e, 0x06, 0x08, 0x2b,
      0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x62, 0x30, 0x60, 0x30, 0x30, 0x06, 0x08,
      0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x24, 0x68, 0x74, 0x74, 0x70, 0x3a,
      0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e,
      0x66, 0x69, 0x2f, 0x63, 0x61, 0x2f, 0x76, 0x72, 0x6b, 0x74, 0x70, 0x33, 0x2e, 0x63, 0x72,
      0x74, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x20, 0x68,
      0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x74, 0x65, 0x73, 0x74, 0x2e,
      0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x76, 0x72, 0x6b, 0x74, 0x70,
      0x33, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
      0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0xb2, 0x24, 0xe5, 0x02, 0x14, 0xa3, 0x41, 0x0a, 0x65,
      0x72, 0xd8, 0x7b, 0x8c, 0xcc, 0x82, 0xb1, 0xd3, 0xba, 0xba, 0xdc, 0xf7, 0x61, 0xec, 0x3d,
      0x34, 0x23, 0xcb, 0x04, 0x92, 0xf1, 0x7d, 0xe6, 0xf1, 0x43, 0x1f, 0x04, 0x4d, 0xe5, 0x0b,
      0x22, 0x10, 0x31, 0x1d, 0xe0, 0x43, 0xcd, 0x56, 0x9d, 0xaa, 0x2f, 0xe4, 0xb7, 0x6d, 0x83,
      0x09, 0x03, 0x91, 0xcb, 0x28, 0x44, 0xb8, 0xb8, 0xa9, 0x05, 0x93, 0x8d, 0x77, 0xc5, 0x82,
      0x14, 0x89, 0xa9, 0xdc, 0x8a, 0xf3, 0x95, 0xff, 0xd1, 0xce, 0xa9, 0xfd, 0x65, 0x6f, 0x95,
      0x3d, 0x92, 0x3c, 0x31, 0xd8, 0x59, 0x5b, 0xcc, 0x30, 0xfe, 0x86, 0xca, 0xf2, 0x8b, 0x63,
      0x70, 0x84, 0x98, 0x50, 0x74, 0x2e, 0x0c, 0x3a, 0xb6, 0x79, 0xb1, 0x24, 0xea, 0xc5, 0x2d,
      0x6a, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x0f, 0xb3, 0xcd, 0x0d, 0x11, 0x56, 0xf6, 0x6d, 0x67, 0x78, 0xd0, 0xac, 0x33, 0x22, 0x12,
      0xb8, 0x5c, 0xcd, 0x61, 0xdf, 0x9d, 0xea, 0xb1, 0x35, 0x97, 0xf5, 0x52, 0x07, 0xab, 0xfb,
      0x35, 0x06, 0x41, 0xb3, 0x3c, 0x03, 0x0f, 0xf6, 0x45, 0x87, 0xdf, 0x07, 0x70, 0x65, 0x26,
      0xe4, 0x26, 0x55, 0x44, 0xc2, 0x47, 0x5b, 0xa1, 0xcb, 0xdd, 0xfe, 0xd2, 0x0b, 0x77, 0x43,
      0x3c, 0xc7, 0x9f, 0x79, 0x8a, 0x1b, 0x3f, 0x2f, 0xb7, 0xf5, 0xd0, 0x83, 0xfb, 0x68, 0xbc,
      0x39, 0x35, 0x61, 0x89, 0x24, 0xc7, 0xb2, 0x43, 0x5f, 0x07, 0x3a, 0x01, 0x2c, 0x55, 0x60,
      0x43, 0x05, 0xd0, 0x19, 0xe7, 0xaf, 0xa7, 0xf5, 0x7b, 0x96, 0x5f, 0x1b, 0x47, 0x18, 0x05,
      0x15, 0x22, 0x40, 0x3e, 0x61, 0x48, 0x9f, 0xf6, 0x98, 0x56, 0x6d, 0x59, 0x8f, 0x23, 0x14,
      0x76, 0x47, 0x06, 0xd5, 0x67, 0x10, 0xd6, 0xc5, 0xc1, 0xaa, 0x18, 0xf7, 0x8e, 0x3e, 0xba,
      0xe6, 0x97, 0x8d, 0x42, 0xb7, 0xbc, 0x1a, 0x14, 0xc3, 0x01, 0xe1, 0x9b, 0x68, 0xc3, 0x20,
      0xac, 0xcf, 0x58, 0x3e, 0x77, 0x43, 0xf6, 0xa6, 0x95, 0x8c, 0xfa, 0xe1, 0x32, 0xb1, 0xb4,
      0x2a, 0xa5, 0x44, 0xf1, 0x4c, 0x08, 0x59, 0x9e, 0x84, 0xc8, 0x2d, 0x2d, 0x59, 0x2e, 0x1d,
      0x95, 0x90, 0x00}},

    {{0x00, 0xb0, 0x05, 0xa8, 0xb5},
     {0x74, 0x83, 0xe8, 0x58, 0x21, 0x04, 0xb2, 0x16, 0x33, 0xd9, 0xde, 0x9c, 0xaf, 0xf3, 0xc9,
      0xfd, 0xd5, 0x07, 0xd9, 0xb4, 0x62, 0x57, 0x53, 0x2d, 0x52, 0x6a, 0xa8, 0x95, 0xa0, 0xec,
      0xbe, 0xe4, 0xcb, 0xe0, 0x38, 0xde, 0x4e, 0x9c, 0xd0, 0x15, 0xca, 0x34, 0xf2, 0x24, 0x6a,
      0x5d, 0x18, 0x4f, 0xfe, 0x6b, 0x07, 0xa3, 0xf2, 0xe2, 0xd9, 0x11, 0xb7, 0x07, 0x72, 0x0d,
      0xcf, 0x4f, 0x50, 0x4b, 0x62, 0x9a, 0xa5, 0xd0, 0x8e, 0x40, 0x0c, 0x5e, 0xa0, 0x12, 0xfb,
      0xa3, 0x77, 0x05, 0x5e, 0x41, 0xf8, 0x68, 0x3c, 0xd7, 0xe7, 0x42, 0x9d, 0xc1, 0xb6, 0x17,
      0x09, 0xe9, 0x87, 0xfb, 0x9a, 0x25, 0x75, 0xb4, 0x5c, 0xfb, 0xfa, 0x18, 0x0f, 0x50, 0xca,
      0xb8, 0x00, 0x10, 0x5b, 0x73, 0x90, 0xce, 0x16, 0xf1, 0xa5, 0x44, 0x87, 0xac, 0xfe, 0xec,
      0x75, 0x67, 0x48, 0x7f, 0xe0, 0x1e, 0xc3, 0x02, 0x4a, 0x46, 0xf5, 0x33, 0x1d, 0x6e, 0xd6,
      0xdf, 0x8c, 0x98, 0x2c, 0x1c, 0xb7, 0x9a, 0x8a, 0x84, 0x9a, 0x1a, 0xad, 0xc6, 0x43, 0x36,
      0x47, 0xfb, 0x99, 0x84, 0x86, 0x75, 0xd5, 0xe6, 0x39, 0xc5, 0xb7, 0x0d, 0xa7, 0x37, 0x51,
      0xa5, 0x95, 0xac, 0xca, 0x34, 0x72, 0x23, 0xef, 0x0f, 0xb0, 0xf4, 0x2f, 0x9c, 0xf5, 0x6f,
      0xf3, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x06, 0x5d, 0x23},
     {0x40, 0x77, 0xb4, 0x91, 0x19, 0xca, 0x66, 0x6f, 0xa9, 0x22, 0xa7, 0xa7, 0xba,
      0x53, 0x5a, 0x07, 0x73, 0xde, 0x67, 0x1f, 0xf0, 0xe1, 0xbb, 0xcf, 0x9d, 0xb4,
      0x51, 0x9e, 0xc3, 0x55, 0xac, 0x9c, 0x19, 0x99, 0xb1, 0x90, 0x00}},

    // 2. PIN Retry count
    // Get retry count
    {{0x00, 0xcb, 0x00, 0xff, 0x05, 0xa0, 0x03, 0x83, 0x01, 0x11, 0x00},
     {0xa0, 0x23, 0x83, 0x01, 0x11, 0x8c, 0x04, 0xf0, 0x00, 0x00, 0x00, 0x9c, 0x04,
      0xf0, 0x00, 0x00, 0x00, 0xdf, 0x21, 0x04, 0x05, 0xff, 0xa5, 0x03, 0xdf, 0x27,
      0x02, 0xff, 0xff, 0xdf, 0x28, 0x01, 0x0c, 0xdf, 0x2f, 0x01, 0x01, 0x90, 0x00}},

    // 3. Authenticate.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x11, 0x0c, 0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x45, 0x84, 0x01, 0x01}, {0x90, 0x00}},

    // Set Hash
    {{0x00, 0x2a, 0x90, 0xa0, 0x22, 0x90, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7,
      0x9f, 0xfd, 0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a,
      0x3f, 0xae, 0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x2a, 0x9e, 0x9a, 0x00},
     {0x4e, 0xdb, 0xd0, 0x2f, 0xb0, 0xd9, 0x61, 0x5f, 0xe8, 0x90, 0x69, 0xb5, 0x81, 0xd8, 0xe5,
      0x4f, 0xcf, 0x14, 0xbf, 0x1d, 0x72, 0x49, 0x74, 0xd3, 0x4e, 0xb5, 0x69, 0x40, 0x07, 0xf6,
      0x55, 0x8e, 0x4b, 0x39, 0x62, 0xd3, 0xe7, 0x2a, 0x0b, 0x41, 0x1e, 0x00, 0xa2, 0x9c, 0x13,
      0x14, 0x6d, 0x4f, 0x1e, 0xc4, 0x8f, 0x4b, 0xbc, 0xbf, 0xe4, 0x5d, 0x57, 0x3e, 0x9b, 0x19,
      0x8f, 0x57, 0x21, 0xa9, 0x1d, 0xa3, 0x28, 0xbb, 0x10, 0x5e, 0x0a, 0x58, 0x02, 0x25, 0xa3,
      0xe1, 0xeb, 0x9a, 0xe5, 0xd6, 0xd8, 0x87, 0xbe, 0x02, 0xa6, 0x40, 0x96, 0x17, 0x53, 0x3e,
      0xf3, 0x5d, 0x63, 0x07, 0x6b, 0xe4, 0x02, 0x16, 0xea, 0x90, 0xed, 0x5c, 0x07, 0xe8, 0x90,
      0xe1, 0x63, 0x36, 0x4d, 0x95, 0xf9, 0x3a, 0xf6, 0xb5, 0x47, 0x20, 0x25, 0xf1, 0x36, 0x4d,
      0xe3, 0xd6, 0x59, 0x81, 0x46, 0xe5, 0xba, 0x44, 0xbc, 0x98, 0x0a, 0xc1, 0x62, 0x8e, 0x0a,
      0x02, 0xf3, 0xe1, 0x92, 0xed, 0x7c, 0x50, 0x7a, 0xcb, 0x4a, 0x9d, 0x58, 0xfd, 0x63, 0x8e,
      0xd4, 0xb7, 0x42, 0x68, 0x0a, 0x2e, 0x10, 0x04, 0xb4, 0xc3, 0x64, 0x86, 0x67, 0x08, 0x9a,
      0x9c, 0x87, 0xee, 0x3a, 0xcd, 0xd5, 0x25, 0x81, 0xbd, 0xba, 0x77, 0x36, 0xfa, 0x8a, 0x88,
      0x5a, 0x14, 0x3e, 0xe8, 0x9d, 0xdb, 0xef, 0xb1, 0x76, 0xe9, 0x73, 0x19, 0x5d, 0x87, 0x1f,
      0x13, 0x81, 0x2b, 0xea, 0xf9, 0xed, 0xd0, 0x8a, 0xb5, 0xda, 0x1f, 0x65, 0x13, 0x3e, 0x9b,
      0x62, 0xeb, 0xce, 0x97, 0x9b, 0x42, 0x00, 0xff, 0x21, 0x8f, 0x6a, 0x50, 0x47, 0xf3, 0xd7,
      0x16, 0xcd, 0xc9, 0x2e, 0x08, 0x82, 0x78, 0x2c, 0x4f, 0xe9, 0x38, 0x2e, 0x4e, 0x7e, 0xbf,
      0xec, 0x69, 0xa7, 0xb9, 0x28, 0x24, 0x18, 0x28, 0xe9, 0xdb, 0x8a, 0xa1, 0x22, 0x46, 0x26,
      0x8c, 0x90, 0x00}}};

const PcscMock::ApduScript FINEID_V3_SELECT_SIGN_CERTIFICATE_AND_SIGNING = {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d,
      0x31, 0x35},
     {0x90, 0x00}},
    // Select signing certificate file.
    {{0x00, 0xA4, 0x08, 0x0C, 0x04, 0x50, 0x16, 0x43, 0x35}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x05, 0xcb, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x05, 0xcb, 0x30, 0x82, 0x03, 0xb3, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04,
      0x06, 0x05, 0x40, 0x46, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
      0x01, 0x0b, 0x05, 0x00, 0x30, 0x74, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
      0x13, 0x02, 0x46, 0x49, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x1a,
      0x56, 0x61, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x6b, 0x69, 0x73, 0x74, 0x65, 0x72, 0x69,
      0x6b, 0x65, 0x73, 0x6b, 0x75, 0x73, 0x20, 0x54, 0x45, 0x53, 0x54, 0x31, 0x18, 0x30, 0x16,
      0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0f, 0x54, 0x65, 0x73, 0x74, 0x69, 0x76, 0x61, 0x72,
      0x6d, 0x65, 0x6e, 0x74, 0x65, 0x65, 0x74, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04,
      0x03, 0x13, 0x1d, 0x56, 0x52, 0x4b, 0x20, 0x43, 0x41, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x54,
      0x65, 0x73, 0x74, 0x20, 0x50, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x73, 0x20, 0x2d, 0x20,
      0x47, 0x33, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x36, 0x30, 0x32, 0x31, 0x31, 0x30,
      0x32, 0x32, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x35, 0x32, 0x32, 0x32, 0x30, 0x35,
      0x39, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x35, 0x39, 0x5a, 0x30, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x46, 0x49, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x09, 0x39,
      0x39, 0x39, 0x30, 0x30, 0x33, 0x33, 0x35, 0x45, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
      0x04, 0x2a, 0x13, 0x05, 0x4c, 0x49, 0x49, 0x53, 0x41, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
      0x55, 0x04, 0x04, 0x13, 0x0f, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x4e,
      0x49, 0x53, 0x59, 0x4a, 0x55, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
      0x1f, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x4e, 0x49, 0x53, 0x59, 0x4a,
      0x55, 0x20, 0x4c, 0x49, 0x49, 0x53, 0x41, 0x20, 0x39, 0x39, 0x39, 0x30, 0x30, 0x33, 0x33,
      0x35, 0x45, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xfa,
      0x23, 0xad, 0x6f, 0x79, 0x77, 0x74, 0x9e, 0x87, 0xd1, 0xe4, 0xc2, 0x4a, 0xd5, 0xf3, 0xec,
      0xf9, 0xb9, 0xd0, 0x10, 0xcd, 0x3e, 0x8b, 0xc2, 0x0d, 0xe0, 0xaf, 0xd0, 0xec, 0x3b, 0xcb,
      0x52, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x29, 0x96, 0x71, 0xa2, 0x90, 0xb5, 0x39, 0x12, 0xa6, 0xe4, 0x62, 0x10, 0x5b, 0xa4, 0xe3,
      0x61, 0x4a, 0x31, 0xff, 0xfd, 0xc7, 0x2d, 0x2f, 0x82, 0x8e, 0x9b, 0x77, 0x10, 0x8e, 0x39,
      0x10, 0xf1, 0xa3, 0x82, 0x02, 0x2d, 0x30, 0x82, 0x02, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55,
      0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x5b, 0xce, 0x86, 0x9c, 0xc7, 0x53, 0x43,
      0xe6, 0x02, 0xb9, 0xfb, 0x71, 0x6c, 0x8c, 0x6d, 0xa3, 0x20, 0xe5, 0xb1, 0xf8, 0x30, 0x1d,
      0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb6, 0x74, 0xa0, 0x95, 0xa4, 0xdd,
      0x79, 0x94, 0x70, 0x26, 0x7a, 0xcf, 0xe2, 0x6e, 0x64, 0x34, 0xed, 0x72, 0x23, 0x2a, 0x30,
      0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x06, 0x40,
      0x30, 0x81, 0xcd, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x81, 0xc5, 0x30, 0x81, 0xc2, 0x30,
      0x81, 0xbf, 0x06, 0x09, 0x2a, 0x81, 0x76, 0x84, 0x05, 0x63, 0x0a, 0x20, 0x01, 0x30, 0x81,
      0xb1, 0x30, 0x27, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1b,
      0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65,
      0x69, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70, 0x73, 0x39, 0x39, 0x2f, 0x30, 0x81, 0x85, 0x06,
      0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x79, 0x1a, 0x77, 0x56, 0x61,
      0x72, 0x6d, 0x65, 0x6e, 0x6e, 0x65, 0x70, 0x6f, 0x6c, 0x69, 0x74, 0x69, 0x69, 0x6b, 0x6b,
      0x61, 0x20, 0x6f, 0x6e, 0x20, 0x73, 0x61, 0x61, 0x74, 0x61, 0x76, 0x69, 0x6c, 0x6c, 0x61,
      0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x6b, 0x61, 0x74, 0x20, 0x70,
      0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x66, 0x69, 0x6e, 0x6e, 0x73, 0x20, 0x2d, 0x20, 0x43,
      0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x70, 0x6f, 0x6c, 0x69,
      0x63, 0x79, 0x20, 0x69, 0x73, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65,
      0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x66, 0x69, 0x6e,
      0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70, 0x73, 0x39, 0x39, 0x30, 0x33, 0x06,
      0x03, 0x55, 0x1d, 0x11, 0x04, 0x2c, 0x30, 0x2a, 0x81, 0x28, 0x47, 0x33, 0x74, 0x65, 0x73,
      0x74, 0x69, 0x4c, 0x69, 0x69, 0x73, 0x61, 0x30, 0x31, 0x36, 0x2e, 0x53, 0x50, 0x45, 0x43,
      0x49, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x4d, 0x45, 0x4e, 0x2d, 0x6e, 0x69, 0x73, 0x79, 0x6a, 0x75, 0x40, 0x74, 0x65, 0x73, 0x74,
      0x69, 0x2e, 0x66, 0x69, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
      0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x37, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x30,
      0x30, 0x2e, 0x30, 0x2c, 0xa0, 0x2a, 0xa0, 0x28, 0x86, 0x26, 0x68, 0x74, 0x74, 0x70, 0x3a,
      0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e,
      0x66, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x76, 0x72, 0x6b, 0x74, 0x70, 0x33, 0x63, 0x2e,
      0x63, 0x72, 0x6c, 0x30, 0x6e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
      0x04, 0x62, 0x30, 0x60, 0x30, 0x30, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
      0x02, 0x86, 0x24, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79,
      0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x61, 0x2f, 0x76,
      0x72, 0x6b, 0x74, 0x70, 0x33, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
      0x6f, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x63, 0x73, 0x70, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e,
      0x66, 0x69, 0x2f, 0x76, 0x72, 0x6b, 0x74, 0x70, 0x33, 0x30, 0x18, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x01, 0x03, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x04,
      0x00, 0x8e, 0x46, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
      0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x59, 0xdc, 0x92, 0x01, 0x14,
      0x5d, 0x37, 0xaf, 0xbb, 0x99, 0xb0, 0x22, 0x3b, 0x44, 0xc0, 0x30, 0x77, 0x41, 0xb3, 0xbd,
      0xc0, 0xae, 0xae, 0x1e, 0x79, 0xb3, 0x47, 0x6d, 0xc6, 0x63, 0xb0, 0x59, 0xba, 0x30, 0x44,
      0xc1, 0xcd, 0x6c, 0xbd, 0xc5, 0x66, 0xd1, 0x12, 0xcc, 0x46, 0xaf, 0x10, 0x36, 0xa1, 0x80,
      0x9d, 0x99, 0x2e, 0xf1, 0x40, 0xba, 0x0a, 0xa8, 0x80, 0xf2, 0x7d, 0x63, 0xa1, 0x27, 0xde,
      0xa0, 0x74, 0xed, 0xcb, 0x05, 0x63, 0xf6, 0x46, 0x95, 0x09, 0xb0, 0x22, 0x84, 0x0b, 0x2e,
      0x50, 0xbb, 0x57, 0x01, 0x61, 0x8b, 0xb5, 0xf1, 0x44, 0x1a, 0x87, 0x4b, 0xe5, 0x14, 0x47,
      0x43, 0x53, 0x5c, 0x31, 0x25, 0x41, 0x2f, 0x17, 0x4e, 0xad, 0x9e, 0x85, 0x2b, 0x00, 0x12,
      0x7b, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x21, 0x1f, 0x01, 0xd6, 0xee, 0xe9, 0x86, 0x00, 0x08, 0xb7, 0xc1, 0x3e, 0xbd, 0x5b, 0xc6,
      0x9e, 0x0f, 0xcb, 0x00, 0x69, 0x4e, 0x6e, 0xd9, 0x58, 0xaa, 0x68, 0x71, 0x7e, 0x7c, 0x42,
      0xad, 0xf2, 0x43, 0x56, 0x01, 0x0c, 0xf6, 0x5e, 0x26, 0xb7, 0x4f, 0x7a, 0x6c, 0xc6, 0xa1,
      0x2e, 0x0e, 0xb4, 0xd8, 0x35, 0x37, 0x6e, 0x06, 0x7e, 0x39, 0xa5, 0x9f, 0x3a, 0xcd, 0x06,
      0x0c, 0xa4, 0xf3, 0xe7, 0x1e, 0xcd, 0xae, 0x3a, 0x29, 0x75, 0xa1, 0xbd, 0x29, 0xb4, 0x9f,
      0x5d, 0x8b, 0x59, 0x66, 0x87, 0x3e, 0x53, 0xcb, 0x16, 0x54, 0xdf, 0xa5, 0x6f, 0x89, 0x2c,
      0x38, 0x38, 0xd7, 0xd9, 0x5f, 0x9a, 0x3a, 0x67, 0x29, 0xd1, 0x5c, 0xb7, 0x3d, 0xd4, 0x88,
      0x58, 0x13, 0x56, 0xc0, 0x11, 0x53, 0xf7, 0xb4, 0x63, 0x44, 0x80, 0x1b, 0x0e, 0x6b, 0xf4,
      0x5d, 0x60, 0xc4, 0x03, 0x22, 0x99, 0x33, 0xf6, 0x86, 0x5a, 0xe2, 0x9e, 0xc6, 0xe3, 0x29,
      0x05, 0x7f, 0xa6, 0x31, 0xd3, 0x93, 0xb5, 0xdb, 0x14, 0x2e, 0x10, 0x8f, 0x58, 0xf4, 0x86,
      0x41, 0x43, 0x14, 0x55, 0x05, 0xdd, 0xc9, 0x9d, 0xde, 0x06, 0x38, 0x9e, 0x0f, 0xbd, 0x1e,
      0xf8, 0x09, 0x0c, 0x9c, 0x0b, 0x6a, 0x39, 0x0d, 0x8d, 0xdf, 0xf3, 0xd6, 0xd0, 0x60, 0x64,
      0xce, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x70, 0x71, 0x7d, 0xea, 0x35, 0xd3, 0xd1, 0x6f, 0x0a, 0xd5, 0xb9, 0x5c, 0x01, 0x22, 0xf4,
      0xc1, 0xf6, 0x89, 0x44, 0xe9, 0x1a, 0x08, 0x5d, 0x32, 0x07, 0x19, 0x3c, 0xc4, 0x7f, 0x65,
      0xe4, 0x7a, 0xdd, 0x69, 0x47, 0xd4, 0x43, 0x10, 0xee, 0xf5, 0x6d, 0xdc, 0x89, 0x40, 0x18,
      0x90, 0x87, 0xb9, 0x02, 0xcd, 0x9a, 0xdf, 0x99, 0x49, 0x7d, 0x9e, 0xa2, 0x1b, 0x4e, 0x17,
      0x58, 0x26, 0x69, 0xee, 0x7b, 0x1d, 0x2f, 0x2d, 0x0c, 0x93, 0x47, 0x14, 0x5a, 0xd5, 0x23,
      0x39, 0x27, 0x4a, 0xc2, 0x41, 0xa2, 0x33, 0xf3, 0xfd, 0xd8, 0x07, 0x0d, 0xc4, 0x88, 0xc4,
      0x4f, 0x71, 0xf4, 0x5d, 0x6b, 0x7f, 0xfa, 0x38, 0xe5, 0x83, 0xf6, 0x44, 0xb0, 0x98, 0xb1,
      0x75, 0x6b, 0xf0, 0x74, 0x39, 0xbc, 0x97, 0x67, 0x7e, 0xc3, 0xa8, 0x41, 0x46, 0x64, 0x6c,
      0xb4, 0x30, 0x9f, 0x50, 0x58, 0x56, 0x8a, 0xe1, 0x86, 0x4c, 0x6d, 0xa4, 0xbf, 0xb9, 0x9f,
      0xb2, 0x15, 0x36, 0x78, 0xba, 0xa7, 0x45, 0x0a, 0x39, 0x0e, 0xcd, 0xba, 0xd6, 0x52, 0x2f,
      0x14, 0xeb, 0x65, 0xfa, 0xba, 0xb9, 0xba, 0x92, 0xca, 0x7a, 0x45, 0x5f, 0x31, 0x19, 0x05,
      0xa5, 0x71, 0xc2, 0x7a, 0xd4, 0xad, 0xea, 0x5e, 0x44, 0x91, 0xf3, 0xfb, 0xd8, 0x63, 0x17,
      0x75, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x05, 0xa8, 0x27},
     {0x37, 0xa8, 0x3b, 0xe9, 0xc2, 0x19, 0x75, 0xa0, 0x97, 0x22, 0xf0, 0x6c, 0x9c, 0x24,
      0x6e, 0xee, 0x15, 0x67, 0x72, 0x01, 0x61, 0x0a, 0xf7, 0x73, 0x98, 0x6c, 0xe8, 0xea,
      0x9c, 0x11, 0xfa, 0xdb, 0x4d, 0x00, 0x34, 0x64, 0x2a, 0xd9, 0xa3, 0x90, 0x00}},

    // 2. PIN Retry count
    // Get retry count
    {{0x00, 0xcb, 0x00, 0xff, 0x05, 0xa0, 0x03, 0x83, 0x01, 0x82, 0x00},
     {0xa0, 0x23, 0x83, 0x01, 0x82, 0x8c, 0x04, 0xf0, 0x00, 0x00, 0x00, 0x9c, 0x04,
      0xf0, 0x00, 0x00, 0x00, 0xdf, 0x21, 0x04, 0x05, 0xff, 0xa5, 0x03, 0xdf, 0x27,
      0x02, 0xff, 0xff, 0xdf, 0x28, 0x01, 0x0c, 0xdf, 0x2f, 0x01, 0x01, 0x90, 0x00}},

    // 3. Signing.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x82, 0x0c, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x44, 0x84, 0x01, 0x03}, {0x90, 0x00}},

    // Set Hash
    {{0x00, 0x2a, 0x90, 0xa0, 0x22, 0x90, 0x20, 0xc0, 0x53, 0x5e, 0x4b, 0xe2, 0xb7,
      0x9f, 0xfd, 0x93, 0x29, 0x13, 0x05, 0x43, 0x6b, 0xf8, 0x89, 0x31, 0x4e, 0x4a,
      0x3f, 0xae, 0xc0, 0x5e, 0xcf, 0xfc, 0xbb, 0x7d, 0xf3, 0x1a, 0xd9, 0xe5, 0x1a},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x2a, 0x9e, 0x9a, 0x40},
     {0x97, 0x8b, 0x91, 0x3d, 0xc8, 0x83, 0x54, 0xa6, 0xbc, 0x61, 0x8a, 0xa6, 0x58, 0x14,
      0x87, 0x97, 0xe3, 0x06, 0xfc, 0x28, 0xea, 0x8b, 0x55, 0xf4, 0x97, 0x50, 0xea, 0xaa,
      0x6b, 0x18, 0x41, 0x7c, 0xe7, 0x9d, 0x92, 0xba, 0x37, 0x47, 0x66, 0x45, 0x13, 0x46,
      0xd9, 0x2c, 0x64, 0x89, 0xd3, 0x0f, 0x27, 0x6f, 0xfc, 0x84, 0xad, 0x47, 0x79, 0x21,
      0x3f, 0x88, 0xc9, 0xd8, 0x0e, 0x96, 0xde, 0x86, 0x90, 0x00}}};
