namespace SecurityCodeScan.Analyzers.Taint
{
    public abstract class BaseCodeEvaluation
    {
        public MethodBehaviorRepository BehaviorRepo { get; set; }
    }
}
