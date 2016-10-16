IF DEFINED PIP (
    ECHO %PYTHON% %PYTHON_VERSION%%APPVEYOR_BUILD_FOLDER%
    set HOME=%APPVEYOR_BUILD_FOLDER%
    %PYPY%
    %PIP% install --upgrade setuptools
    %PIP% install pytest-coverage codecov cryptography wheel
    cd %HOME%
    %RUN% -m pytest -c setup.cfg --cov=./py_src/ ./py_src/ || goto :error
    %RUN% setup.py sdist --universal
    %PIP% install --no-index --find-links=.\\dist\\ py2p
    %RUN% setup.py bdist_wheel
    %RUN% setup.py build
    FOR /F %%v IN ('%RUN% -c "import sys, sysconfig; print(\"{}.{}-{v[0]}.{v[1]}\".format(\"lib\", sysconfig.get_platform(), v=sys.version_info))"') DO SET BUILD_DIR=%%v
    ren .coverage .covvv
    %RUN% -m pytest -c setup.cfg --cov=build\\%BUILD_DIR% build\\%BUILD_DIR% || goto :error
    ren .covvv .coverage.1
    ren .coverage .coverage.2
    %COV% combine
    %COV% xml
    %RUN% -c "import codecov; codecov.main('--token=d89f9bd9-27a3-4560-8dbb-39ee3ba020a5', '--file=coverage.xml')"
) ELSE (
    dir C:\avvm\node
    powershell -Command "Install-Product node $env:NODE"
    npm install .
    npm install -g mocha babel-cli
    mocha js_src\\test\\* || goto :error
    babel js_src --out-dir build\\es5
    mocha build\\es5\\test\\* || goto :error
)
goto :EOF

:error
ECHO Failed with error #%errorlevel%.
exit /b %errorlevel%
