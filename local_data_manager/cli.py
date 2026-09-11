import click
from rich.console import Console
from rich.table import Table
from database import get_session
from models import Collaborator, Work, WorkAuthor, Collaboration
import manage_data

console = Console()

@click.group()
def cli():
    """Research Network Data Manager CLI"""
    pass

# --- COLLABORATORS ---
@cli.group()
def collabs():
    """Manage Collaborators (Add, List, Delete, Update)"""
    pass

@collabs.command('list')
def list_collabs():
    """List all collaborators"""
    session = get_session()
    table = Table(title="Collaborators")
    table.add_column("Nickname", justify="left", style="cyan", no_wrap=True)
    table.add_column("Full Name", style="magenta")
    table.add_column("Institution", style="green")
    table.add_column("Is Me", style="yellow")
    
    for c in session.query(Collaborator).all():
        table.add_row(c.nickname, c.full_name, c.institution or "", str(c.is_self))
        
    console.print(table)

@collabs.command('add')
@click.option('--nickname', prompt=True, help='Short handle for author (e.g. jdoe)')
@click.option('--fullname', prompt="Full Name")
@click.option('--email', default="")
@click.option('--affiliation', default="")
@click.option('--department', default="")
@click.option('--position', default="")
@click.option('--institution', default="", help="Institution")
@click.option('--country', default="")
@click.option('--city', default="")
@click.option('--website', default="")
@click.option('--orcid', default="")
@click.option('--scholar', 'google_scholar_url', default="")
@click.option('--linkedin', 'linkedin_url', default="")
@click.option('--bio', is_flag=True, help="Prompt interactively to enter a multi-line bio")
def add_collab(nickname, fullname, email, affiliation, department, position, institution, country, city, website, orcid, google_scholar_url, linkedin_url, bio):
    """Add a new collaborator"""
    session = get_session()
    c = session.query(Collaborator).filter_by(nickname=nickname).first()
    if c:
        console.print(f"[red]Error: Nickname '{nickname}' already exists![/red]")
        return
        
    bio_text = None
    if bio:
        bio_text = get_multiline_input("Enter Bio:")
        
    c = Collaborator(
        nickname=nickname, 
        full_name=fullname,
        email=email if email else None,
        affiliation=affiliation if affiliation else None,
        department=department if department else None,
        position=position if position else None,
        institution=institution if institution else None,
        country=country if country else None,
        city=city if city else None,
        website=website if website else None,
        orcid=orcid if orcid else None,
        google_scholar_url=google_scholar_url if google_scholar_url else None,
        linkedin_url=linkedin_url if linkedin_url else None,
        bio=bio_text
    )
    session.add(c)
    session.commit()
    console.print(f"[green]Successfully added collaborator: {fullname} ({nickname})[/green]")

@collabs.command('update')
@click.argument('nickname')
@click.option('--fullname', help="New full name")
@click.option('--email', help="New email")
@click.option('--affiliation', help="New affiliation")
@click.option('--department', help="New department")
@click.option('--position', help="New position")
@click.option('--institution', help="New institution")
@click.option('--country', help="New country")
@click.option('--city', help="New city")
@click.option('--website', help="New website")
@click.option('--orcid', help="New ORCID")
@click.option('--scholar', 'google_scholar_url', help="New Google Scholar URL")
@click.option('--linkedin', 'linkedin_url', help="New LinkedIn URL")
@click.option('--bio', is_flag=True, help="Prompt interactively to enter a multi-line bio")
def update_collab(nickname, fullname, email, affiliation, department, position, institution, country, city, website, orcid, google_scholar_url, linkedin_url, bio):
    """Update an existing collaborator"""
    session = get_session()
    c = session.query(Collaborator).filter_by(nickname=nickname).first()
    if not c:
        console.print(f"[red]Error: Collaborator '{nickname}' not found.[/red]")
        return
    
    if fullname is not None: c.full_name = fullname
    if email is not None: c.email = email
    if affiliation is not None: c.affiliation = affiliation
    if department is not None: c.department = department
    if position is not None: c.position = position
    if institution is not None: c.institution = institution
    if country is not None: c.country = country
    if city is not None: c.city = city
    if website is not None: c.website = website
    if orcid is not None: c.orcid = orcid
    if google_scholar_url is not None: c.google_scholar_url = google_scholar_url
    if linkedin_url is not None: c.linkedin_url = linkedin_url
    
    if bio:
        c.bio = get_multiline_input("Enter new Bio:")
    
    session.commit()
    console.print(f"[green]Successfully updated collaborator '{nickname}'.[/green]")

@collabs.command('delete')
@click.argument('nickname')
def delete_collab(nickname):
    """Delete a collaborator by nickname"""
    session = get_session()
    c = session.query(Collaborator).filter_by(nickname=nickname).first()
    if c:
        if c.is_self:
            console.print("[red]Error: Cannot delete the 'self' collaborator.[/red]")
            return
        session.delete(c)
        session.commit()
        console.print(f"[green]Deleted collaborator '{nickname}'[/green]")
    else:
        console.print(f"[red]Not found: {nickname}[/red]")

@collabs.command('connect')
@click.argument('nick1')
@click.argument('nick2')
@click.option('--status', type=click.Choice(['established', 'ongoing']), default='established')
def connect_collab(nick1, nick2, status):
    """Establish a connection between two collaborators by their nicknames"""
    session = get_session()
    c1 = session.query(Collaborator).filter_by(nickname=nick1).first()
    c2 = session.query(Collaborator).filter_by(nickname=nick2).first()
    if not c1 or not c2:
        console.print("[red]Error: One or both collaborators not found.[/red]")
        return
    c1.add_collaboration(session, c2, status=status)
    session.commit()
    console.print(f"[green]Successfully connected {nick1} and {nick2} as {status}[/green]")

@collabs.command('disconnect')
@click.argument('nick1')
@click.argument('nick2')
def disconnect_collab(nick1, nick2):
    """Remove a connection between two collaborators"""
    session = get_session()
    c1 = session.query(Collaborator).filter_by(nickname=nick1).first()
    c2 = session.query(Collaborator).filter_by(nickname=nick2).first()
    if not c1 or not c2:
        console.print("[red]Error: One or both collaborators not found.[/red]")
        return
    id1, id2 = sorted([c1.id, c2.id])
    existing = session.query(Collaboration).filter_by(collaborator1_id=id1, collaborator2_id=id2).first()
    if existing:
        session.delete(existing)
        session.commit()
        console.print(f"[green]Successfully disconnected {nick1} and {nick2}[/green]")
    else:
        console.print(f"[yellow]No connection existed between {nick1} and {nick2}[/yellow]")

# --- WORKS ---
@cli.group()
def works():
    """Manage Works (Add, List, Delete, Update)"""
    pass

@works.command('list')
def list_works():
    """List all works"""
    session = get_session()
    table = Table(title="Research Works")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Order", justify="right", style="magenta")
    table.add_column("Title", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("Authors", style="blue")
    
    for w in session.query(Work).order_by(Work.display_order.asc()).all():
        sorted_was = sorted(w.authors, key=lambda wa: wa.collaborator.full_name.split()[-1].lower())
        authors = ", ".join([wa.collaborator.nickname for wa in sorted_was if wa.collaborator.nickname])
        table.add_row(w.id, str(w.display_order), w.title, w.work_type, authors)
        
    console.print(table)

def get_multiline_input(prompt_text):
    console.print(f"[bold cyan]{prompt_text}[/bold cyan]")
    console.print("[dim](Paste your text below. When done, press Enter on an empty line twice, or type 'END' on a new line and press Enter.)[/dim]")
    lines = []
    empty_count = 0
    while True:
        try:
            line = input()
            if line.strip() == "END":
                break
            if not line.strip():
                empty_count += 1
                if empty_count >= 2:
                    if lines and not lines[-1].strip():
                        lines.pop()
                    break
            else:
                empty_count = 0
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines).strip()

@works.command('add')
@click.option('--title', prompt=True)
@click.option('--subtitle', default="", help="Subtitle")
@click.option('--publisher', default="", help="Publisher")
@click.option('--url', default="", help="General URL")
@click.option('--pdf', 'pdf_url', default="", help="PDF URL")
@click.option('--notes', is_flag=True, help="Prompt interactively to enter multi-line notes")
@click.option('--status', default="published", help="Status (e.g. published, preprint)")
@click.option('--type', 'work_type', type=click.Choice(['publication', 'preprint', 'ongoing']), prompt=True)
@click.option('--year', prompt=True, type=str, default="")
@click.option('--date', 'publication_date', prompt="Publication Date (e.g. Nov 2024)", default="")
@click.option('--arxiv', 'arxiv_id', default="", help="arXiv ID")
@click.option('--doi', default="", help="DOI")
@click.option('--journal', 'journal_conference', default="", help="Journal or Conference name")
@click.option('--volume', default="", help="Volume")
@click.option('--issue', default="", help="Issue")
@click.option('--pages', default="", help="Pages")
@click.option('--rg', 'researchgate_url', default="", help="ResearchGate URL")
@click.option('--order', 'display_order', type=int, default=0, help="Order index (lowest prints first)")
@click.option('--authors', prompt="Authors (comma separated nicknames, e.g. 'me,jdoe')", help="Comma-separated list of author nicknames in order")
@click.option('--abstract', is_flag=True, help="Prompt interactively to enter a multi-line abstract")
def add_work(title, subtitle, publisher, url, pdf_url, notes, status, work_type, year, publication_date, arxiv_id, doi, journal_conference, volume, issue, pages, researchgate_url, display_order, authors, abstract):
    """Add a new research work"""
    session = get_session()
    
    # parse year
    year_val = None
    if year.isdigit():
        year_val = int(year)
        
    abstract_text = None
    if abstract:
        abstract_text = get_multiline_input("Enter Abstract:")
        
    notes_text = None
    if notes:
        notes_text = get_multiline_input("Enter Notes:")
        
    w = Work(
        title=title,
        status=status,
        subtitle=subtitle if subtitle else None,
        publisher=publisher if publisher else None,
        url=url if url else None,
        pdf_url=pdf_url if pdf_url else None,
        notes=notes_text,
 
        work_type=work_type, 
        year=year_val,
        publication_date=publication_date if publication_date else None,
        arxiv_id=arxiv_id if arxiv_id else None,
        doi=doi if doi else None,
        journal_conference=journal_conference if journal_conference else None,
        volume=volume if volume else None,
        issue=issue if issue else None,
        pages=pages if pages else None,
        researchgate_url=researchgate_url if researchgate_url else None,
        display_order=display_order,
        abstract=abstract_text
    )
    session.add(w)
    session.flush()
    
    author_list = [a.strip() for a in authors.split(',') if a.strip()]
    for i, nick in enumerate(author_list):
        c = session.query(Collaborator).filter_by(nickname=nick).first()
        if c:
            wa = WorkAuthor(work_id=w.id, collaborator_id=c.id, author_order=i+1)
            session.add(wa)
        else:
            console.print(f"[yellow]Warning: Author nickname '{nick}' not found. Skipping...[/yellow]")
            
    session.commit()
    console.print(f"[green]Successfully added work: '{title}' (ID: {w.id})[/green]")

@works.command('update')
@click.argument('work_id')
@click.option('--title', help="New title")
@click.option('--subtitle', help="New subtitle")
@click.option('--publisher', help="New publisher")
@click.option('--url', help="New general URL")
@click.option('--pdf', 'pdf_url', help="New PDF URL")
@click.option('--notes', is_flag=True, help="Prompt interactively to enter multi-line notes")
@click.option('--status', default="published", help="Status (e.g. published, preprint)")
@click.option('--status', help="New status")
@click.option('--type', 'work_type', type=click.Choice(['publication', 'preprint', 'ongoing']))
@click.option('--year', type=int)
@click.option('--date', 'publication_date', help="Publication Date")
@click.option('--arxiv', 'arxiv_id', help="arXiv ID")
@click.option('--doi', help="DOI")
@click.option('--journal', 'journal_conference', help="Journal or Conference name")
@click.option('--volume', help="Volume")
@click.option('--issue', help="Issue")
@click.option('--pages', help="Pages")
@click.option('--rg', 'researchgate_url', help="ResearchGate URL")
@click.option('--order', 'display_order', type=int, help="Display order index")
@click.option('--authors', help="Comma separated nicknames to completely replace current authors")
@click.option('--abstract', is_flag=True, help="Prompt interactively to enter a multi-line abstract")
def update_work(work_id, title, subtitle, publisher, url, pdf_url, notes, status, work_type, year, publication_date, arxiv_id, doi, journal_conference, volume, issue, pages, researchgate_url, display_order, authors, abstract):
    """Update an existing work"""
    session = get_session()
    w = session.get(Work, work_id)
    if not w:
        console.print(f"[red]Error: Work with ID '{work_id}' not found.[/red]")
        return
        
    if title is not None: w.title = title
    if status is not None: w.status = status
    if subtitle is not None: w.subtitle = subtitle
    if publisher is not None: w.publisher = publisher
    if url is not None: w.url = url
    if pdf_url is not None: w.pdf_url = pdf_url
    if notes: w.notes = get_multiline_input("Enter new Notes:")
    if work_type is not None: w.work_type = work_type
    if year is not None: w.year = year
    if publication_date is not None: w.publication_date = publication_date
    if arxiv_id is not None: w.arxiv_id = arxiv_id
    if doi is not None: w.doi = doi
    if journal_conference is not None: w.journal_conference = journal_conference
    if volume is not None: w.volume = volume
    if issue is not None: w.issue = issue
    if pages is not None: w.pages = pages
    if researchgate_url is not None: w.researchgate_url = researchgate_url
    if display_order is not None: w.display_order = display_order
    
    if abstract:
        w.abstract = get_multiline_input("Enter new Abstract:")
    
    if authors is not None:
        # delete existing
        for wa in w.authors:
            session.delete(wa)
        session.flush()
        
        author_list = [a.strip() for a in authors.split(',') if a.strip()]
        for i, nick in enumerate(author_list):
            c = session.query(Collaborator).filter_by(nickname=nick).first()
            if c:
                wa = WorkAuthor(work_id=w.id, collaborator_id=c.id, author_order=i+1)
                session.add(wa)
            else:
                console.print(f"[yellow]Warning: Author nickname '{nick}' not found. Skipping...[/yellow]")
                
    session.commit()
    console.print(f"[green]Successfully updated work '{work_id}'.[/green]")

@works.command('delete')
@click.argument('work_id')
def delete_work(work_id):
    """Delete a work by ID"""
    session = get_session()
    w = session.get(Work, work_id)
    if w:
        title = w.title
        session.delete(w)
        session.commit()
        console.print(f"[green]Deleted work '{title}' ({work_id})[/green]")
    else:
        console.print(f"[red]Not found: {work_id}[/red]")

# --- ROOT COMMANDS ---
@cli.command()
def export():
    """Export the SQLite database to Flask JSON files"""
    manage_data.do_export()
    console.print("[bold green]JSON Export Complete! Ready for Flask.[/bold green]")

if __name__ == '__main__':
    cli()


