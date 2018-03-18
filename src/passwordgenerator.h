#ifndef PASSWORDGENERATOR_H
#define PASSWORDGENERATOR_H

#include <QString>

class PasswordGenerator
{
public:
  PasswordGenerator();

private:
  QString charset;
  unsigned int length;

  QString generateNative();
  QString generatePwGen();
  QString generateCustom();
  quint32 boundedRandom(quint32 bound);
};

#endif // PASSWORDGENERATOR_H
