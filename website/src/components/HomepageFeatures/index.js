import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Real Hardware MicroVMs',
    Svg: require('@site/static/img/logo.svg').default,
    description: (
      <>
        Built on <code>crun-krun</code>, libkrun, and Linux KVM. Your code runs inside
        a real, isolated Linux microVM kernel that boots in ~100ms, without the heavy overhead
        of traditional virtual machines.
      </>
    ),
  },
  {
    title: 'Keep Agents on a Leash',
    Svg: require('@site/static/img/logo.svg').default,
    description: (
      <>
        Lock down network egress right from the host. Only let your agent talk to AI endpoints
        or software registries, and watch what it connects to with real-time domain traffic stats.
      </>
    ),
  },
  {
    title: 'Native Libadwaita & CLI',
    Svg: require('@site/static/img/logo.svg').default,
    description: (
      <>
        A clean, snappy GTK4 desktop console that uses ~30 MB of RAM (no bloated Electron),
        respects your GNOME theme, and pairs with a comprehensive CLI for power users.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
