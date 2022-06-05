using AutoMapper;
using SecureApi.Data;
using SecureApi.Models;

namespace SecureApi.Helpers;

public class MapProfile : Profile
{
    public MapProfile()
    {
        CreateMap<ApplicationUser, RegisterModel>()
        .ForMember(m => m.Password, opt => opt.Ignore())
        .ReverseMap();
    }
}