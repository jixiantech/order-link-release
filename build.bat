@echo off
chcp 65001
echo 开始打包极限苹果订单管理系统...

:: 安装依赖
echo 安装依赖...
py -m pip install pyqt5
py -m pip install requests
py -m pip install beautifulsoup4
py -m pip install openpyxl
py -m pip install pyinstaller

:: 打包
echo 打包中...
py -m PyInstaller --onedir --windowed --name "极限link" --icon "favicon.ico" gui.py

:: 打包成 zip
echo 压缩成 zip...
powershell Compress-Archive -Path "dist\极限link\*" -DestinationPath "极限link.zip" -Force

echo.
echo 打包完成！
echo zip 文件：极限link.zip
echo 上传到 GitHub Releases 即可
pause