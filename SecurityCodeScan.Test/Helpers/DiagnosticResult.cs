using System;
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
        private DiagnosticResultLocation[] LocationsField;

        public DiagnosticResultLocation[] Locations
        {
            get => LocationsField ?? (LocationsField = new DiagnosticResultLocation[] { });
            set => LocationsField = value;
        }

        public DiagnosticSeverity? Severity { get; set; }

        public string Id { get; set; }

        public string Message { get; set; }

        public int Line => Locations.Length > 0 ? Locations[0].Line : -1;

        public int Column => Locations.Length > 0 ? Locations[0].Column : -1;

        //TODO: Find a better way to specify .vb

        public DiagnosticResult WithLocation(int line)
        {
            return WithLocation("Test0.cs", line, -1);
        }

        public DiagnosticResult WithLocation(int line, int column)
        {
            return WithLocation("Test0.cs", line, column);
        }

        public DiagnosticResult WithLocation(string path, int line)
        {
            return WithLocation(path, line, -1);
        }

        public DiagnosticResult WithLocation(string path, int line, int column)
        {
            DiagnosticResult result = this;
            Array.Resize(ref result.LocationsField, (result.LocationsField?.Length ?? 0) + 1);
            result.LocationsField[result.LocationsField.Length - 1] = new DiagnosticResultLocation(path, line, column);
            return result;
        }
    }
}
