/* Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "phonenumbers/phonenumbermatcher.h"
#include <string>
#include <vector>

#include <unicode/unistr.h>

#include "phonenumbers/base/basictypes.h"
#include "phonenumbers/base/memory/scoped_ptr.h"
#include "phonenumbers/base/memory/singleton.h"
#include "phonenumbers/default_logger.h"
#include "phonenumbers/phonenumber.h"
#include "phonenumbers/phonenumber.pb.h"
#include "phonenumbers/phonenumbermatch.h"
#include "phonenumbers/phonenumberutil.h"
#include "phonenumbers/stringutil.h"

#include <fuzzer/FuzzedDataProvider.h>


// General-purpose fuzzer for the parser
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    i18n::phonenumbers::PhoneNumberUtil *phone_util = i18n::phonenumbers::PhoneNumberUtil::GetInstance();

    FuzzedDataProvider fuzzed_data(data, size);

    // Random region for functions which require
    // a region parameter
    std::string region = fuzzed_data.ConsumeRandomLengthString();
    // std::string region2 = fuzzed_data.ConsumeRandomLengthString();

    i18n::phonenumbers::PhoneNumber phone_parsed;
    std::string number = fuzzed_data.ConsumeRandomLengthString();
    phone_util->ParseHelper(number, region, fuzzed_data.ConsumeBool(), fuzzed_data.ConsumeBool(), &phone_parsed);

    // Create a second number used for fuzzing comparison functions
    // and functions which affect the state of a given PhoneNumber
    i18n::phonenumbers::PhoneNumber phone_parsed2;
    std::string number2 = fuzzed_data.ConsumeRandomLengthString();
    phone_util->ParseHelper(number2, region2, fuzzed_data.ConsumeBool(), fuzzed_data.ConsumeBool(), &phone_parsed2);

    phone_util->IsPossibleNumberForString(&number2);
    phone_util->IsAlphaNumber(&number2);
    phone_util->IsValidNumber(&number2);
    phone_util->IsValidNumberForRegion(&phone_parsed, &region);
    phone_util->IsPossibleNumber(phone_parsed);    
    phone_util->IsNationalNumberSuffixOfTheOther(phone_parsed, phone_parsed2);
    phone_util->IsNumberMatchWithTwoStrings(&number, &number2);
    phone_util->IsNumberMatchWithTwoStrings(&phone_parsed, &number2);
    phone_util->IsNumberMatch(&phone_parsed, &phone_parsed2);
    phone_util->CanBeInternationallyDialled(&phone_parsed);
    phone_util->GetNumberType(&phone_parsed);
    phone_util->GetLengthOfGeographicalAreaCode(&phone_parsed);
    phone_util->GetLengthOfNationalDestinationCode(&phone_parsed);
    phone_util->IsNANPACountry(&region);
    phone_util->GetCountryCodeForRegion(&region);
    phone_util_.IsPossibleNumberForType(
      number, PhoneNumberUtil::FIXED_LINE_OR_MOBILE);
    phone_util_.TruncateTooLongNumber(
      number, PhoneNumberUtil::FIXED_LINE_OR_MOBILE);

    // normalizeshit
    phone_util->IsNumberGeographical(&phone_parsed);
    int num = fuzzed_data.ConsumeIntegral();
    phone_util->IsNumberGeographical(&phone_parsed, num);

    std::string out;
    phone_util->GetNationalSignificantNumber(&phone_parsed, &out);
    phone_util->GetLengthOfGeographicalAreaCode(&phone_parsed);
    phone_util->GetLengthOfNationalDestinationCode(&phone_parsed);

    std::string out1;
    int num1 = fuzzed_data.ConsumeIntegral();
    phone_util->GetCountryMobileToken(num1, &out1);

    std::string out2;
    phone_util->GetRegionCodeForNumber(&phone_parsed, &out2);

    std::string out3;
    phone_util->GetNddPrefixForRegion(&region, fuzzed_data.ConsumeBool(), &out3);

    // ParseAndKeepRawInput or parse
    // ConvertFromTelephoneNumberProto
    return 0;
}
