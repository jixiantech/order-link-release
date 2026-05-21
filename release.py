"""
release.py - Mac 上一键发布新版本
用法: python release.py 1.0.2

功能：
1. 更新 version.txt
2. Git commit + push 到 GitHub
"""

import sys
import os
import subprocess

GITHUB_USER = "jixiantech"
GITHUB_REPO = "order-link-release"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def run(cmd, check=True):
    print(f">> {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=PROJECT_DIR)
    if result.stdout.strip(): print(result.stdout)
    if result.stderr.strip(): print(result.stderr)
    if check and result.returncode != 0:
        print(f"❌ 命令失败: {cmd}")
        sys.exit(1)
    return result

def main():
    if len(sys.argv) < 2:
        print("用法: python release.py 版本号")
        print("例如: python release.py 1.0.2")
        sys.exit(1)

    version = sys.argv[1].strip()
    print(f"\n🚀 开始发布版本 {version}\n")

    # Step 1: 更新 version.txt
    print("Step 1: 更新 version.txt...")
    version_path = os.path.join(PROJECT_DIR, "version.txt")
    with open(version_path, 'w') as f:
        f.write(version)
    print(f"✅ version.txt 更新为 {version}")

    # Step 2: Git commit + push
    print("\nStep 2: Git 提交推送...")
    run('git add version.txt')
    run(f'git commit -m "Release v{version}"')
    run('git push origin main')
    print("✅ 推送完成")

    print(f"\n🎉 发布完成！版本 v{version} 已推送到 GitHub")
    print(f"📌 接下来在 Windows 上运行 build.bat 打包，然后上传到：")
    print(f"   https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases/new")
    print(f"   记得把 tag 设置为 v{version}，上传 极限link.zip")

if __name__ == "__main__":
    main()