/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2021 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder,
 * Tim Gueneysu, Jan Richter-Brockmann.
 * Contact: drucker.nir@gmail.com, shay.gueron@gmail.com,
 * rafaelmisoczki@google.com, tobias.oder@rub.de, tim.gueneysu@rub.de,
 * jan.richter-brockmann@rub.de.
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/


#ifndef _R_DECAPS_H_
#define _R_DECAPS_H_

#include "types.h"
#include "conversions.h"

// transpose a row into a column:
_INLINE_ void transpose(uint8_t col[R_BITS], uint8_t row[R_BITS])
{
    col[0] = row[0];
    for (uint64_t i = 1; i < R_BITS ; ++i)
    {
        col[i] = row[(R_BITS) - i];
    }
}

// Count number of 1's in tmp:
uint32_t getHammingWeight(const uint8_t tmp[R_BITS], const uint32_t length);

int BGF_decoder(uint8_t e[R_BITS*2],
        uint8_t s[R_BITS],
        uint32_t h0_compact[DV],
        uint32_t h1_compact[DV]);

#endif //_R_DECAPS_H_
