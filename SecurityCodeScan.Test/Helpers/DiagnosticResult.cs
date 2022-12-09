using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Test.Helpers
{
    /// <summary>
    /// Location where the diagnostic appears, as determined by path, line number, and column number.
    /// </summary>
    public struct DiagnosticResultLocation
    {
        public DiagnosticResultLocation()
        {
            Line = -1;
            Column = -1;
            Path = $"{DiagnosticVerifier.DefaultFilePathPrefix}0";
        }

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
        public DiagnosticResult()
        {
        }

        public DiagnosticResultLocation Location { get; private set; } = new DiagnosticResultLocation();

        private List<DiagnosticResultLocation> AdditionalLocationsField;

        public IReadOnlyList<DiagnosticResultLocation> AdditionalLocations => AdditionalLocationsField;

        public DiagnosticSeverity? Severity { get; set; }

        public string Id { get; set; }

        public string Message { get; set; }

        public int Line => Location.Line;

        public int Column => Location.Column;

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
            result.Location = new DiagnosticResultLocation(path, line, column);

            return result;
        }

        public DiagnosticResult WithAdditionalLocations(List<ResultAdditionalLocation> resultLocations)
        {
            DiagnosticResult result = this;
            var path = $"{DiagnosticVerifier.DefaultFilePathPrefix}0";
            if (result.AdditionalLocationsField == null)
                result.AdditionalLocationsField = new List<DiagnosticResultLocation>();

            result.AdditionalLocationsField.AddRange(resultLocations.Select(l => new DiagnosticResultLocation(path, l.Line, l.Column)));
            
            return result;
        }

    }

    public struct ResultAdditionalLocation
    {
        public ResultAdditionalLocation(int line, int column)
        {
            Line = line;
            Column = column;
        }

        public int Line { get; }
        public int Column { get; }
    }
}
