param(
    [string]$InputPath = 'previews/affected.ansi',
    [string]$OutputPath = 'previews/scan-results.png'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$taskLines = Get-Content -LiteralPath $InputPath -Encoding utf8
$taskCell = 10
$taskRow = 21
$taskImage = [System.Drawing.Bitmap]::new(820, (($taskLines.Count + 2) * $taskRow))
$taskGraphics = [System.Drawing.Graphics]::FromImage($taskImage)
$taskFont = [System.Drawing.Font]::new('Consolas', 16, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
try {
    $taskGraphics.Clear([System.Drawing.Color]::FromArgb(9,12,18))
    $taskGraphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    for ($taskRowIndex = 0; $taskRowIndex -lt $taskLines.Count; $taskRowIndex++) {
        $taskColor = [System.Drawing.Color]::FromArgb(194,203,214)
        $taskColumn = 0
        foreach ($taskSegment in [regex]::Split($taskLines[$taskRowIndex], '(\x1b\[[0-9;]*m)')) {
            if ($taskSegment -match '^\x1b\[([0-9;]*)m$') {
                $taskCodes = $Matches[1]
                if ($taskCodes -match '38;5;(\d+)') {
                    $taskIndex = [int]$Matches[1]
                    if ($taskIndex -ge 232) {
                        $taskGray = 8 + 10 * ($taskIndex - 232)
                        $taskColor = [System.Drawing.Color]::FromArgb($taskGray,$taskGray,$taskGray)
                    } elseif ($taskIndex -ge 16) {
                        $taskIndex -= 16
                        $taskSteps = @(0,95,135,175,215,255)
                        $taskColor = [System.Drawing.Color]::FromArgb($taskSteps[[int][math]::Floor($taskIndex / 36)], $taskSteps[[int][math]::Floor(($taskIndex % 36) / 6)], $taskSteps[$taskIndex % 6])
                    }
                } else { $taskColor = [System.Drawing.Color]::FromArgb(194,203,214) }
                continue
            }
            $taskBrush = [System.Drawing.SolidBrush]::new($taskColor)
            try {
                foreach ($taskCharacter in $taskSegment.ToCharArray()) {
                    $taskX = 10 + $taskColumn * $taskCell
                    $taskY = 14 + $taskRowIndex * $taskRow
                    $taskGraphics.DrawString([string]$taskCharacter, $taskFont, $taskBrush, $taskX, $taskY, [System.Drawing.StringFormat]::GenericTypographic)
                    $taskColumn++
                }
            } finally { $taskBrush.Dispose() }
        }
    }
    $taskImage.Save([System.IO.Path]::GetFullPath($OutputPath), [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $taskFont.Dispose()
    $taskGraphics.Dispose()
    $taskImage.Dispose()
}
