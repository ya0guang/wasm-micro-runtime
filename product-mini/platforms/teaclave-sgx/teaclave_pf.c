/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
unsigned int teaclave_open(char* fid, int* out_handle);

int
atoi(const char *str)
{
    int result = 0;
    int sign = 0;
    // proc whitespace characters
    while (*str == ' ' || *str == '\t' || *str == '\n')
        ++str;

    // proc sign character
    if (*str == '-') {
        sign = 1;
        ++str;
    }
    else if (*str == '+') {
        ++str;
    }

    // proc numbers
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + *str - '0';
        ++str;
    }

    // return result
    if (sign == 1)
        return -result;
    else
        return result;
}

int
entrypoint(int argc, char *argv[])
{
    // if (argc < 4) {
    //     return -1;
    // }
    
    // if ((argv[0] == 0) || argv[2] == 0) {
    //     return -1;
    // }
    char* input_fid = "pf_in";
    int input_handle = 10086;
    
    int rv = teaclave_open("111", &input_handle);
    return rv;

    // return atoi(argv[1]) + atoi(argv[3]);
}
