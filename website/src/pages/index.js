import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';

import Heading from '@theme/Heading';
import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Get Started - Documentation
          </Link>
        </div>
      </div>
    </header>
  );
}

function ShowcasePreview() {
  return (
    <section style={{padding: '2.5rem 0 1rem 0', textAlign: 'center'}}>
      <div className="container">
        <div style={{maxWidth: '960px', margin: '0 auto', borderRadius: '12px', overflow: 'hidden', boxShadow: '0 8px 32px rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)'}}>
          <img
            src="/krunbox/img/screenshots/main-window.png"
            alt="krunbox GTK4 and Libadwaita console preview"
            style={{width: '100%', display: 'block'}}
          />
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title="MicroVM Sandboxes for Linux"
      description="Run autonomous AI agents and untrusted code inside fast, hardware-isolated microVMs with egress controls and a native GTK4 GUI">
      <HomepageHeader />
      <main>
        <ShowcasePreview />
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
