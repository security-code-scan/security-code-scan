namespace SecurityCodeScan.Analyzers.Taint
{
    public enum VariableTaint
    {
        /// <summary>
        /// Constant string
        /// </summary>
        Constant,
        /// <summary>
        /// Value that are safe to use
        /// </summary>
        Safe,
        /// <summary>
        /// Value obtain from an external sources
        /// </summary>
        Unknown,
        /// <summary>
        /// Value taken from input source.
        /// </summary>
        Tainted
    }
}
