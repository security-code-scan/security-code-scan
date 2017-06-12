using Microsoft.CodeAnalysis;
using System;

namespace TestHelper
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

            this.Path = path;
            this.Line = line;
            this.Column = column;
        }

        public string Path { get; }
        public int Line { get; }
        public int Column { get; }
    }

    /// <summary>
    /// Struct that stores information about a Diagnostic appearing in a source
    /// </summary>
    public struct DiagnosticResult
    {
        private DiagnosticResultLocation[] locations;

        public DiagnosticResultLocation[] Locations
        {
            get
            {
                if (this.locations == null)
                {
                    this.locations = new DiagnosticResultLocation[] { };
                }
                return this.locations;
            }

            set
            {
                this.locations = value;
            }
        }

        public DiagnosticSeverity Severity { get; set; }

        public string Id { get; set; }

        public string Message { get; set; }

        public string Path
        {
            get
            {
                return this.Locations.Length > 0 ? this.Locations[0].Path : "";
            }
        }

        public int Line
        {
            get
            {
                return this.Locations.Length > 0 ? this.Locations[0].Line : -1;
            }
        }

        public int Column
        {
            get
            {
                return this.Locations.Length > 0 ? this.Locations[0].Column : -1;
            }
        }

        //TODO: Find a better way to specify .vb

        public DiagnosticResult WithLocation(int line)
        {
            return this.WithLocation("Test0.cs", line, -1);
        }

        public DiagnosticResult WithLocation(int line, int column)
        {
            return this.WithLocation("Test0.cs", line, column);
        }

        public DiagnosticResult WithLocation(string path, int line)
        {
            return this.WithLocation(path, line, -1);
        }

        public DiagnosticResult WithLocation(string path, int line, int column)
        {
            DiagnosticResult result = this;
            Array.Resize(ref result.locations, (result.locations?.Length ?? 0) + 1);
            result.locations[result.locations.Length - 1] = new DiagnosticResultLocation(path, line, column);
            return result;
        }
    }
}