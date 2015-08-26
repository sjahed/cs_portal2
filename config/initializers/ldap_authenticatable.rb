require 'net/ldap'
require 'devise/strategies/authenticatable'

module Devise
	module Strategies
		class LdapAuthenticatable < Authenticatable
			def authenticate!
				if params[:user]
					
					ldap = Net::LDAP.new
					ldap.host = "dir.wmich.edu"
					ldap.port = 389
					ldap.auth "uid=caelab,ou=special,ou=people,o=wmich.edu,dc=wmich,dc=edu", "Scotty<>Terrier"
					
					result = ldap.bind_as(
						:base => "ou=people,o=wmich.edu,dc=wmich,dc=edu",
						:filter => "mail=#{email}",
						:password => password
					)

					if result 
						user = User.find_or_create_by(email: email)
						success!(user)
					else
						fail(:invalid_login)
					end

				end#end of if  params[:user]
			end

			def email
				params[:user][:email]
			end
			
			def password
				params[:user][:password]
			end
		end
	end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)
