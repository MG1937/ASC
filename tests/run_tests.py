import os
import subprocess
import sys
import shutil

WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
AGENT_SCRIPT = os.path.join(WORKSPACE_ROOT, "agent_operator.py")

MEITUAN_APK = os.path.join(WORKSPACE_ROOT, "meituan.apk")
MEITUAN_CLASS = "Lcom/meituan/android/cashier/activity/MTCashierWrapperActivity;"

def run_test(apk_path, clazz_name):
    print(f"\n{'='*80}")
    print(f"Testing APK: {apk_path}")
    print(f"Class: {clazz_name}")
    print(f"{'='*80}\n")
    
    cmd = [sys.executable, AGENT_SCRIPT, "getclass", "-v", apk_path, clazz_name]
    
    print(f"Running command: {' '.join(cmd)}\n")
    
    process = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
    
    print(process.stdout)
    if process.stderr:
        print(f"STDERR:\n{process.stderr}")
    
    if process.returncode == 0 and "class" in process.stdout.lower():
        print("\n[SUCCESS] Test passed! Got decompiled code.")
    else:
        print(f"\n[FAILED] Test failed with return code {process.returncode}")
    
    return process.returncode

def main():
    temp_dir = os.path.join(WORKSPACE_ROOT, "temp")
    if os.path.exists(temp_dir):
        print(f"Cleaning temp directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    print("Starting NewTool tests...")
    
    if os.path.exists(MEITUAN_APK):
        rc = run_test(MEITUAN_APK, MEITUAN_CLASS)
        sys.exit(rc)
    else:
        print(f"[SKIP] {MEITUAN_APK} not found")
        sys.exit(1)

if __name__ == "__main__":
    main()
