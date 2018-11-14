using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Location where the diagnostic appears, as determined by path, line number, and column number.
    /// </summary>
    public struct DiagnosticResultLocation
    {
        public DiagnosticResultLocation(string path, int line, int column)
        {
            if (line < -1)
            {
                throw new ArgumentOutOfRangeException(nameof(line), "line must be >= -1");
            }

            if (column < -1)
            {
                throw new ArgumentOutOfRangeException(nameof(column), "column must be >= -1");
            }

            Path   = path;
            Line   = line;
            Column = column;
        }

        public string Path   { get; }
        public int    Line   { get; }
        public int    Column { get; }
    }

    /// <summary>
    /// Struct that stores information about a Diagnostic appearing in a source
    /// </summary>
    public struct DiagnosticResult
    {
        private List<DiagnosticResultLocation> LocationsField;

        public IReadOnlyList<DiagnosticResultLocation> Locations => LocationsField;

        public DiagnosticSeverity? Severity { get; set; }

        public string Id { get; set; }

        public string Message { get; set; }

        public int Line => LocationsField != null ? Locations[0].Line : -1;

        public int Column => LocationsField != null ? Locations[0].Column : -1;

        public DiagnosticResult WithMessage(string message)
        {
            DiagnosticResult result = this;
            result.Message = message;
            return result;
        }

        public DiagnosticResult WithLocation(int line)
        {
            return WithLocation($"{DiagnosticVerifier.DefaultFilePathPrefix}0", line, -1);
        }

        public DiagnosticResult WithLocation(int line, int column)
        {
            return WithLocation($"{DiagnosticVerifier.DefaultFilePathPrefix}0", line, column);
        }

        private DiagnosticResult WithLocation(string path, int line, int column)
        {
            DiagnosticResult result = this;
            if (result.LocationsField == null)
                result.LocationsField = new List<DiagnosticResultLocation>(1);

            result.LocationsField.Add(new DiagnosticResultLocation(path, line, column));
            return result;
        }
    }
}
