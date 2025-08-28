#!/usr/bin/env python3
import pandas as pd
import json
import re
import sys
import copy


class PIIDetectorRedactor:
    def __init__(self):
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b') 
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_pattern = re.compile(r'\b[\w\d\.]+@[a-zA-Z]+\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.full_name_pattern = re.compile(r'\b[A-Z][a-zA-Z]+\s+[A-Z][a-zA-Z]+\b')
        self.pin_pattern = re.compile(r'\b\d{6}\b')
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
    def normalize_number(self, value, expected_length):
        try:
            str_value = str(value)
            if 'e+' in str_value.lower():
                num = int(float(value))
                if len(str(num)) == expected_length:
                    return str(num)
        except:
            pass
        return str(value)
    
    def detect_standalone_pii(self, data):
        pii_fields = set()
        for key, value in data.items():
            if value is None:
                continue
            str_value = str(value)
            
            if key == 'phone':
                normalized = self.normalize_number(str_value, 10)
                if self.phone_pattern.fullmatch(normalized):
                    pii_fields.add(key)
            elif self.phone_pattern.search(str_value):
                pii_fields.add(key)
            elif key == 'aadhar':
                normalized = self.normalize_number(str_value, 12)
                if self.aadhar_pattern.fullmatch(normalized):
                    pii_fields.add(key)
            elif self.aadhar_pattern.search(str_value):
                pii_fields.add(key)
            elif key == 'passport' and self.passport_pattern.search(str_value):
                pii_fields.add(key)
            elif key == 'upi_id' and self.upi_pattern.search(str_value):
                pii_fields.add(key)
                
        return pii_fields
    
    def detect_combinatorial_pii(self, data):
        combinatorial_elements = []
        
        for key, value in data.items():
            if value is None:
                continue
            str_value = str(value).strip()
            
            if key == 'name' and self.full_name_pattern.search(str_value):
                combinatorial_elements.append(('identity', key))
            elif key in ['first_name', 'last_name'] and len(str_value) > 1:
                combinatorial_elements.append(('identity', key))
            elif key == 'email' and self.email_pattern.search(str_value):
                combinatorial_elements.append(('contact', key))
            elif key == 'address' and len(str_value) > 10:
                if self.pin_pattern.search(str_value) or ',' in str_value:
                    combinatorial_elements.append(('location', key))
            elif key in ['city', 'state'] and len(str_value) > 1:
                combinatorial_elements.append(('location', key))
            elif key in ['pin_code', 'pincode'] and self.pin_pattern.search(str_value):
                combinatorial_elements.append(('location', key))
            elif key in ['device_id'] and len(str_value) > 3:
                combinatorial_elements.append(('device', key))
            elif key == 'ip_address' and self.ip_pattern.search(str_value):
                combinatorial_elements.append(('device', key))
        
        pii_fields = set()
        has_first_name = any(key == 'first_name' for _, key in combinatorial_elements)
        has_last_name = any(key == 'last_name' for _, key in combinatorial_elements) 
        if has_first_name and has_last_name:
            pii_fields.update(['first_name', 'last_name'])
        
        element_categories = set([category for category, _ in combinatorial_elements])
        if len(element_categories) >= 2:
            pii_fields.update([key for _, key in combinatorial_elements])
            
        return pii_fields
    
    def redact_value(self, key, value):
        if value is None:
            return None
        str_value = str(value)
        
        if key == 'phone':
            normalized = self.normalize_number(str_value, 10)
            if len(normalized) == 10 and normalized.isdigit():
                return f"{normalized[:2]}XXXXXX{normalized[-2:]}"
            return "98XXXXXX10"
        elif key == 'aadhar':
            normalized = self.normalize_number(str_value, 12) 
            if len(normalized) == 12 and normalized.isdigit():
                return f"{normalized[:3]}XXXXXXX{normalized[-2:]}"
            return "123XXXXXXX12"
        elif key == 'passport':
            return f"{str_value[0]}XXXXXXX" if len(str_value) >= 8 else "PXXXXXXX"
        elif key == 'upi_id':
            if '@' in str_value:
                parts = str_value.split('@')
                return f"{parts[0][:2]}XXXX@{parts[1]}"
            return f"{str_value[:2]}XXXX"
        elif key in ['name', 'first_name', 'last_name']:
            words = str_value.split()
            return ' '.join([f"{word[0]}{'X'*(len(word)-1)}" if len(word) > 1 else 'X' for word in words])
        elif key == 'email':
            if '@' in str_value:
                local, domain = str_value.split('@', 1)
                redacted_local = f"{local[:2]}{'X'*(len(local)-2)}" if len(local) > 2 else 'XX'
                return f"{redacted_local}@{domain}"
        elif key == 'address':
            return "[REDACTED_ADDRESS]"
        elif key == 'ip_address':
            parts = str_value.split('.')
            return f"{parts[0]}.XXX.XXX.{parts[3]}" if len(parts) == 4 else "XXX.XXX.XXX.XXX"
        elif key in ['city', 'state', 'pin_code']:
            return "[REDACTED_PII]"
        return "[REDACTED_PII]"
    
    def process_record(self, record_data):
        redacted_data = copy.deepcopy(record_data)
        standalone_pii = self.detect_standalone_pii(record_data)
        combinatorial_pii = self.detect_combinatorial_pii(record_data) 
        all_pii_fields = standalone_pii.union(combinatorial_pii)
        
        for field in all_pii_fields:
            if field in redacted_data:
                redacted_data[field] = self.redact_value(field, record_data[field])
        
        is_pii = len(all_pii_fields) > 0
        return redacted_data, is_pii

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "redacted_output_candidate_full_name.csv"
    
    try:
        print(f"Loading input file: {input_file}")
        df = pd.read_csv(input_file)
        detector = PIIDetectorRedactor()
        results = []
        total_records = len(df)
        pii_count = 0
        
        print(f"Processing {total_records} records...")
        
        for idx, row in df.iterrows():
            try:
                json_data = json.loads(row['data_json'])
                redacted_data, is_pii = detector.process_record(json_data)
                
                results.append({
                    'record_id': row['record_id'],
                    'redacted_data_json': json.dumps(redacted_data, separators=(',', ':')),
                    'is_pii': is_pii
                })
                
                if is_pii:
                    pii_count += 1
                
                if (idx + 1) % 50 == 0:
                    print(f"Processed {idx + 1}/{total_records} records...")
                    
            except Exception as e:
                results.append({
                    'record_id': row['record_id'],
                    'redacted_data_json': row['data_json'],
                    'is_pii': False
                })
        
        output_df = pd.DataFrame(results)
        output_df.to_csv(output_file, index=False)
        
        print(f"\nProcessing complete!")
        print(f"Total records processed: {total_records}")
        print(f"Records with PII: {pii_count}")
        print(f"Records without PII: {total_records - pii_count}")
        print(f"Output saved to: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
