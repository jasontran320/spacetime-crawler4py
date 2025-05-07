import re
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
import os
import nltk
from nltk.corpus import stopwords


REPORT_THRESHOLD = 200
# Tracking variables for report
unique_urls = set()
unique_subdomains = defaultdict(int)
word_count = Counter()
longest_page = {
    'url': None,
    'word_count': 0
}

try:
    STOP_WORDS = set(stopwords.words('english'))
except LookupError:
    nltk.download('stopwords')
    STOP_WORDS = set(stopwords.words('english'))


def tokenize(text):
    current_token = ""
    for char in text:
        if char.isalnum() and char.isascii():
            current_token += char.lower()
        elif current_token:
            # Yields token if it is 3 or more characters and isn't a stop word
            if len(current_token) >= 3 and current_token not in STOP_WORDS:
                yield current_token
            current_token = ""
    
    # Same as above for last token
    if current_token and len(current_token) >= 3 and current_token not in STOP_WORDS:
        yield current_token

def track_logs(url, resp, soup): 
    global word_count
    global longest_page
    global unique_urls
    global unique_subdomains
    try:
        # Extract texts from all relevent tags
        body_element = soup.find('body')
        # Extract all text with appropriate spacing
        if body_element:
            text = body_element.get_text(separator=' ', strip=True)
            
            # Generate valid tokens from text
            tokens = list(tokenize(text))
            
            # Update word frequencies
            word_count.update(tokens)
            
            # Update longest page if current is longer
            token_count = len(tokens)

            if token_count > longest_page['word_count']:
                longest_page['word_count'] = token_count
                longest_page['url'] = resp.url
        
        # Defrag current url
        defragged_url, _ = urldefrag(resp.url)
        
        if defragged_url not in unique_urls:
            unique_urls.add(defragged_url)
            # Extract and count subdomain
            parsed_url = urlparse(defragged_url)
            subdomain = parsed_url.netloc
            
            unique_subdomains[subdomain] += 1

    except Exception as e:
        print(f"Error processing {url}: {e}")

def is_valid_response(resp):
    if resp.status != 200:
        return False
    # Check if there's an error in the response
    if resp.error:
        return False
    # Check if content exists
    if not resp.raw_response or not resp.raw_response.content:
        return False
    # Checks if file not too large - 10MB limit
    content_length = len(resp.raw_response.content)
    if content_length > 10 * 1024 * 1024:
        return False
    return True

def scraper(url, resp):
    if not is_valid_response(resp):
        return []
    try:
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        track_logs(url, resp, soup) #Logic for updating logging information 
        # Extract links and validate them
        links = extract_next_links(url, resp, soup)
        valid_links = [link for link in links if is_valid(link)]
        if len(unique_urls) % REPORT_THRESHOLD == 0:
            print('updating report')
            generate_report()
        return valid_links
    
    except Exception as e:
        print(f"Error processing {url}: {e}")
        return []

def extract_next_links(url, resp, soup):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    try:
        # Find all links in the page
        links = []
        for a_tag in soup.find_all('a', href=True):
            # Get the link
            link = a_tag['href']
            # Make relative URLs absolute
            absolute_link = urljoin(resp.url, link)
            # Remove fragment part of the URL
            defragged_link, _ = urldefrag(absolute_link)
            # Add to our list of links
            links.append(defragged_link)
        return links
    
    except Exception as e:
        print(f"Error processing {url}: {e}")
        return []


def special_case(parsed):
    # Special case for today.uci.edu
    if parsed.netloc == "today.uci.edu":
        return parsed.path.startswith("/department/information_computer_sciences/")
    return False

def has_large_integer_in_path(parsed_path, threshold=100000):
    matches = re.findall(r'/(\d+)(?:/|\.|$)', parsed_path)
    for num in matches:
        if int(num) > threshold:
            return True
    return False

def has_multiple_path_segment(path, segment, threshold=2):
    pattern = fr'/{re.escape(segment)}(?=/|$)'
    matches = re.findall(pattern, path.lower())
    return len(matches) >= threshold

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        
        # Check if http or https
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # Check if the URL is within the allowed domains
        allowed_domains = [
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        ]
        
        # Check if the domain is in the allowed list
        # if (not any(parsed.netloc.endswith(domain) for domain in allowed_domains)) and not special_case(parsed):
        #     return False
        
        if not ( any(parsed.netloc == domain or parsed.netloc.endswith(f".{domain}") for domain in allowed_domains)) and not special_case(parsed):
            return False

        # Block ics wiki pages - most content behind login
        if parsed.netloc.endswith("wiki.ics.uci.edu"):
            return False

        # Check for query parameters that might lead to crawler traps
        if parsed.query and re.search(r"(date|ical|action|filter|share|eventdisplay|c=|o=|do=media)", parsed.query.lower()):
            return False

        # Check for specific patterns that indicate content to avoid
        if re.search(r"(/pix/|deldroid|/pdf/|login|emws09/emws09|git@gitlab.ics.uci.edu:|facebook|twitter|wp-content/uploads|/-/|/t?sld\d+\.htm|/pubs/[^/]*[ap]-)", url.lower()):
            return False

        if has_large_integer_in_path(parsed.path):
            return False

        if has_multiple_path_segment(parsed.path, 'seminar', 2):
            return False
        
        # Detect date patterns in URLs that might indicate calendar pages
        date_pattern = re.compile(
            r"\b\d{4}[-/]\d{2}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{2}[-/]\d{4}\b|"
            r"\b\d{4}[-/]\d{2}\b|"
            r"\b\d{2}[-/]\d{4}\b"
        )
        if bool(date_pattern.search(url)):
            path = parsed.path.strip("/")
            segments = path.split("/")
            # white list articles
            # e.g., /2023/10/02/article-title
            if (
                parsed.netloc == "ics.uci.edu" and 
                len(segments) == 4 and
                '-' in segments[3] and
                segments[3][0].isalpha() and
                segments[0].isdigit() and
                segments[1].isdigit() and
                segments[2].isdigit() and
                2020 <= int(segments[0]) <= 2025 and
                1 <= int(segments[1]) <= 12 and       # Month must be valid
                1 <= int(segments[2]) <= 31           # Day must be valid
            ):
                pass
            else:
                return False


        # Detect and limit pagination to avoid traps. Filters out pages over the fifth in pagination
        page_match = re.search(r"(?:(?:\?|&)page=|/page/)(\d+)", url)
        if page_match:
            page_num = int(page_match.group(1))
            if page_num > 5:
                return False
        
        # Filter out non-webpage files
        if re.search(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ppsx|bib|sql"  # Added extensions
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv|h|cp|lif|txt|git|bam|war|java|conf|mol|ff|sh|c|tsv|xml|py|can|db|svg|odc|m|pps"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)(?:[\?#]|$)", parsed.path.lower()):  # Updated pattern end
            return False
        
        if len(parsed.path.split('/')) > 7:  # Avoid deep directory structures
            return False
        
        return True
    
        
    except TypeError:
        print(f"TypeError for {url}")
        return False
    except Exception as e:
        print(f"Error validating {url}: {e}")
        return False


def generate_report():
    # Create a directory for reports if it doesn't exist
    os.makedirs("report", exist_ok=True)
    
    # Number of unique pages
    with open("report/unique_pages.txt", "w") as f:
        f.write(f"Number of unique pages: {len(unique_urls)}\n")
    
    # Longest page
    with open("report/longest_page.txt", "w") as f:
        f.write(f"Longest page: {longest_page['url']} with {longest_page['word_count']} words\n")
    
    # 50 most common words
    with open("report/common_words.txt", "w") as f:
        f.write("50 most common words:\n")
        for i, (word, count) in enumerate(word_count.most_common(50), 1):
            f.write(f"{i}. {word}: {count}\n")
    
    # Subdomains ordered alphabetically
    with open("report/subdomains.txt", "w") as f:
        f.write("Subdomains and their page counts:\n")
        for subdomain in sorted(unique_subdomains.keys()):
            f.write(f"{subdomain}, {unique_subdomains[subdomain]}\n")
            
    print("Report files generated in the 'report' directory")