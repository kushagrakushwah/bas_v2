from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

from reportlab.lib.pagesizes import letter

# ---------------------------------------------------
# PDF REPORT GENERATOR
# ---------------------------------------------------

def generate_pdf_report(
    output_path,
    title,
    summary_text
):

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            title,
            styles["Title"]
        )
    )

    elements.append(
        Spacer(1, 20)
    )

    for line in summary_text.split("\n"):

        elements.append(
            Paragraph(
                line,
                styles["BodyText"]
            )
        )

        elements.append(
            Spacer(1, 8)
        )

    doc.build(elements)

    return output_path