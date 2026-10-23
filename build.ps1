param([switch]$Test)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$classDirectory = Join-Path $projectRoot 'build/classes'
New-Item -ItemType Directory -Path $classDirectory -Force | Out-Null
$sources = @(Get-ChildItem (Join-Path $projectRoot 'src/main') -Filter '*.java' -Recurse | ForEach-Object FullName)
if ($Test) { $sources += @(Get-ChildItem (Join-Path $projectRoot 'src/test') -Filter '*.java' -Recurse | ForEach-Object FullName) }
& javac --release 21 -Xlint:all -Werror -d $classDirectory $sources
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
if ($Test) {
    & java -cp $classDirectory portfolio.jar.ArchiveAuditTests
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
}
& jar --create --file (Join-Path $projectRoot 'build/jar-surface-auditor.jar') --main-class portfolio.jar.Main -C $classDirectory portfolio/jar
if ($LASTEXITCODE -ne 0) { throw 'JAR packaging failed' }
