#include "passwordgenerator.h"
#include "qtpasssettings.h"

#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QRandomGenerator>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

PasswordGenerator::PasswordGenerator()
{

}

QString PasswordGenerator::generateNative() {
  unsigned int length = QtPassSettings::getPasswordConfiguration().length;
  QString out;
  for (unsigned int i = 0; i < length; ++i) {
    out.append(charset.at(static_cast<int>(
        boundedRandom(static_cast<quint32>(charset.length())))));
  }
  return out;
}

QString PasswordGenerator::generatePwGen() {
  // --secure goes first as it overrides --no-* otherwise
  QString passwd;
  Executor exec;
  QStringList args;
  args.append("-1");
  if (QtPassSettings::isLessRandom())
    args.append("--secure");
  args.append(QtPassSettings::isAvoidCapitals() ? "--no-capitalize"
                                                : "--capitalize");
  args.append(QtPassSettings::isAvoidNumbers() ? "--no-numerals"
                                               : "--numerals");
  if (QtPassSettings::isUseSymbols())
    args.append("--symbols");
  args.append(QString::number(length));
  QString p_out;
  //  TODO(bezet): try-catch here(2 statuses to merge o_O)
  if (exec.executeBlocking(QtPassSettings::getPwgenExecutable(), args,
                           &passwd) == 0)
    passwd.remove(QRegExp("[\\n\\r]"));
  else {
    passwd.clear();
    qDebug() << __FILE__ << ":" << __LINE__ << "\t"
             << "pwgen fail";
    //    TODO(bezet): emit critical ?
  }
  return passwd;
}


/* Copyright (C) 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
quint32 PasswordGenerator::boundedRandom(quint32 bound) {
  if (bound < 2) {
    return 0;
  }

  quint32 randval;
  const quint32 max_mod_bound = (1 + ~bound) % bound;

#if QT_VERSION < QT_VERSION_CHECK(5, 10, 0)
  static int fd = -1;
  if (fd == -1) {
    assert((fd = open("/dev/urandom", O_RDONLY)) >= 0);
  }
#endif

  do {
#if QT_VERSION < QT_VERSION_CHECK(5, 10, 0)
    assert(read(fd, &randval, sizeof(randval)) == sizeof(randval));
#else
    randval = QRandomGenerator::system()->generate();
#endif
  } while (randval < max_mod_bound);

  return randval % bound;
}
