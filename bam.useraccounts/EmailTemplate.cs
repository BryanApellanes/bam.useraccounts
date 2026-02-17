namespace Bam.Messaging
{
    public class EmailTemplate
    {
        public string EmailName { get; set; } = null!;
        public bool IsHtml { get; set; }
        public string TemplateContent { get; set; } = null!;
    }
}
