import sys
import os

# استيراد الفئات والدوال من الوحدات الأخرى التي بنيناها (Modular Architecture)
from logic import TriageScanner
from utils import generate_sha256, export_to_json

def main():
    print("=== DFIR Triage Automation Tool ===")
    
    # 1. Interactive CLI & Input Validation
    # إذا لم يقم المستخدم بتمرير مسار المجلد في سطر الأوامر، سيسأله البرنامج بشكل تفاعلي
    if len(sys.argv) > 1:
        target_folder = sys.argv[1]
    else:
        target_folder = input("[?] Enter the path to the evidence folder to scan: ").strip()

    # التحقق من صحة المدخلات (Input Validation)
    if not os.path.isdir(target_folder):
        print(f"[-] Error: The folder '{target_folder}' does not exist.")
        sys.exit(1)

    print(f"\n[*] Initializing scan on: {target_folder}...")
    
    try:
        # 2. Object-Oriented Programming (OOP) Integration
        # تهيئة فئة الفحص
        scanner = TriageScanner(target_folder)
        
        # جمع البيانات
        processes = scanner.get_running_processes()
        recent_files = scanner.get_recent_files(window_seconds=600)  # فحص ملفات آخر 10 دقائق
        
        # 3. Data Processing (Hashing)
        file_hashes = {}
        for file_info in recent_files:
            filename = file_info["filename"]
            filepath = os.path.join(target_folder, filename)
            # استدعاء دالة التشفير من ملف utils
            file_hashes[filename] = generate_sha256(filepath)
        
        # 4. Report Generation
        report_data = {
            "target_directory": target_folder,
            "running_processes_sample": processes,
            "recent_activity": recent_files,
            "cryptographic_hashes": file_hashes
        }
        
        # طباعة ملخص سريع على الشاشة
        print("\n--- Triage Report Summary ---")
        print(f"[+] Processes Sampled: {len(processes)}")
        if recent_files:
            for rf in recent_files:
                name = rf['filename']
                age = rf['age_seconds']
                short_hash = file_hashes[name][:12]
                print(f"  [!] {name} (modified {age}s ago) -> SHA-256: {short_hash}...")
        else:
            print("  [-] No recent file modifications detected.")
            
        # 5. Data Persistence
        # حفظ التقرير النهائي بصيغة JSON في مجلد data
        output_file = os.path.join("data", "triage_report.json")
        export_to_json(report_data, output_file)
        
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

# ضمان تشغيل الكود فقط إذا تم استدعاء هذا الملف مباشرة
if __name__ == "__main__":
    main()